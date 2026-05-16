"""
app.py — SkillChain Flask API.

Startup sequence
----------------
1. Create Flask app + rate limiter.
2. Run DB migrations (idempotent — safe on every deploy).
3. Initialise certificate and DID tables.
4. Register all routes.

CHANGES (stabilization pass):
  - /request-registration and /admin/approve honour http_status from service dict.
  - /issue checks institution wallet readiness before anchoring (Fix 3).
  - All routes wrapped in try/except returning JSON errors — no stack traces (Fix 10).

CHANGES (DID pass):
  - /did/<path:did> constructs a W3C-compliant DID document directly from did_registry.
    No longer depends on w3c_did_service for resolution; that service is kept for
    pre-generation/caching only.

CHANGES (demo-hardening pass):
  - GET /institution/wallet — returns wallet address + funding status, no private keys.
  - /request-registration rewrites verify_url to use request.url_root so the link
    works on Railway/Render/localhost without hardcoding.
"""
from dotenv import load_dotenv
load_dotenv()
import hashlib
import io
import logging
import os
import re
import secrets
import time
import zipfile
import json as _json

from flask import Flask, request, jsonify, render_template
try:
    from flask_cors import CORS
except ImportError:
    CORS = None
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from PIL import Image

from algorand_service import init_db, anchor_hash, verify_hash, get_algod_client, generate_hmac, save_to_db
from signing_service import sign_credential_hash, sign_transaction
from algosdk import transaction as algo_txn_mod
from algosdk.transaction import wait_for_confirmation
from did_service import (
    init_did_db,
    validate_api_key,
    register_did,
    sign_credential,
    request_registration,
    verify_email_token,
    get_pending_registrations,
    approve_registration,
    get_algod_client as get_did_algod_client,  # aliased — avoid collision with algorand_service
)
from digilocker_service import (
    create_digilocker_request,
    get_request_status,
    verify_with_identity,
)
from identity_service import bind_identity, lookup_identity
from queue_service import queue_batch, get_batch_status
from ipfs_service import pin_with_retry
import db_migrations
from db import (
    dict_cursor,
    get_db_connection,
    get_sqlalchemy_database_uri,
    is_production_deployment,
    using_sqlite_fallback,
)
from models import db, Artwork, ProvenanceEvent
from services.payment_service import create_acquisition_order, record_successful_acquisition
from x402_service import create_payment_requirements, verify_x402_payment

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ── App + rate limiter ────────────────────────────────────────────────────────
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = get_sqlalchemy_database_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
frontend_url=os.getenv("FRONTEND_URL",
                      "http://localhost:5173"
                    )
db.init_app(app)

if using_sqlite_fallback():
    log.warning(
        "Flask app configured with SQLite development fallback: %s",
        app.config["SQLALCHEMY_DATABASE_URI"],
    )
else:
    log.info("Flask app configured with Postgres database.")

CORS(app)


limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day"],
)

ARTWORK = {
    "id": "art_001",
    "title": "Handwoven Textile",
    "price_usdc": 1,
}


def _seed_x402_artwork() -> None:
    artwork = db.session.get(Artwork, ARTWORK["id"])
    if artwork is not None:
        return

    db.session.add(
        Artwork(
            id=ARTWORK["id"],
            title=ARTWORK["title"],
            current_owner=None,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
    )
    db.session.commit()


def _record_x402_acquisition(wallet_address: str, settlement_reference: str | None) -> dict:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    artwork = db.session.get(Artwork, ARTWORK["id"])
    if artwork is None:
        raise ValueError("Demo artwork not found")

    artwork.current_owner = wallet_address
    db.session.add(
        ProvenanceEvent(
            artwork_id=artwork.id,
            owner_wallet=wallet_address,
            event_type="acquisition_recorded",
            settlement_reference=settlement_reference,
            created_at=now,
        )
    )
    db.session.commit()
    return {
        "status": "ownership_transferred",
        "artwork_id": artwork.id,
        "owner": wallet_address,
        "provenance_event": "acquisition_recorded",
        "network": "algorand-testnet",
        "updated_at": now,
    }


# ── Commerce (Domestic Settlement v1 — Razorpay UPI) ─────────────────────────

@app.route("/acquire-artwork", methods=["POST"])
@limiter.limit("30 per minute")
def acquire_artwork():
    try:
        payload = request.get_json(silent=True) or {}
        requested_artwork_id = payload.get("artwork_id", ARTWORK["id"])

        if requested_artwork_id != ARTWORK["id"]:
            return jsonify(
                {
                    "error": "Artwork not found",
                    "available_artwork_id": ARTWORK["id"],
                }
            ), 404

        verification = verify_x402_payment(request.headers)
        if not verification.get("verified"):
            return (
                jsonify(
                    {
                        "error": "Payment Required",
                        "artwork": ARTWORK,
                        "payment_requirements": create_payment_requirements(),
                    }
                ),
                402,
            )

        wallet_address = verification.get("wallet_address") or "wallet_address"
        settlement = verification.get("settlement") or {}
        result = _record_x402_acquisition(
            wallet_address,
            settlement.get("settlement_reference"),
        )
        result["settlement"] = verification.get("settlement")
        return jsonify(result), 200
    except Exception as exc:
        db.session.rollback()
        log.error("acquire_artwork error: %s", exc)
        return jsonify({"error": "Artwork acquisition failed", "detail": str(exc)}), 500


@app.route("/artwork/<artwork_id>", methods=["GET"])
@limiter.limit("60 per minute")
def get_x402_artwork(artwork_id: str):
    try:
        # TEMP DEMO MOCK
        if artwork_id == "art_001":
            return jsonify({
                "artwork": {
                    "id": "art_001",
                    "title": "Handwoven Textile",
                    "created_at": "2026-05-15T12:00:00Z",
                    "artisan_did": "did:skillchain:testnet:artisan001",
                    "description": "Blockchain-certified artisan textile."
                },
                "current_owner": "Original Collector",
                "provenance_history": [
                    {
                        "id": "evt_001",
                        "event_type": "CERTIFIED",
                        "owner_wallet": "ALGO_OWNER_001",
                        "settlement_reference": "ALGOTX123",
                        "created_at": "2026-05-15T12:00:00Z"
                    }
                ]
            }), 200
        artwork = db.session.get(Artwork, artwork_id)
        if artwork is None:
            return jsonify({"error": "Artwork not found"}), 404

        history = (
            ProvenanceEvent.query
            .filter_by(artwork_id=artwork_id)
            .order_by(ProvenanceEvent.created_at.asc(), ProvenanceEvent.id.asc())
            .all()
        )
        return jsonify(
            {
                "artwork": {
                    "id": artwork.id,
                    "title": artwork.title,
                    "created_at": artwork.created_at,
                },
                "current_owner": artwork.current_owner,
                "provenance_history": [
                    {
                        "id": event.id,
                        "artwork_id": event.artwork_id,
                        "owner_wallet": event.owner_wallet,
                        "event_type": event.event_type,
                        "settlement_reference": event.settlement_reference,
                        "created_at": event.created_at,
                    }
                    for event in history
                ],
            }
        ), 200
    except Exception as exc:
        log.error("get_x402_artwork error: %s", exc)
        return jsonify({"error": "Could not fetch artwork", "detail": str(exc)}), 500


@app.route("/api/payments/create-order", methods=["POST"])
@limiter.limit("30 per minute")
def payments_create_order():
    try:
        data = request.get_json(silent=True) or {}
        artwork_id = data.get("artwork_id")
        # Prefer provenance-native language. Keep legacy aliases for compatibility.
        collector_name = data.get("collector_name", "") or data.get("buyer_name", "")
        collector_email = data.get("collector_email", "") or data.get("buyer_email", "")

        if artwork_id is None:
            return jsonify({"error": "artwork_id is required"}), 400
        try:
            artwork_id = int(artwork_id)
        except Exception:
            return jsonify({"error": "artwork_id must be an integer"}), 400

        payload = create_acquisition_order(
            artwork_id=artwork_id,
            buyer_name=collector_name,
            buyer_email=collector_email,
        )
        return jsonify({"success": True, **payload})
    except KeyError as exc:
        return jsonify({"error": "Artwork not found", "detail": str(exc)}), 404
    except Exception as exc:
        log.error("payments_create_order error: %s", exc)
        return jsonify({"error": "Order creation failed", "detail": str(exc)}), 500


@app.route("/api/payments/verify-payment", methods=["POST"])
@limiter.limit("60 per minute")
def payments_verify_payment():
    try:
        data = request.get_json(silent=True) or {}
        order_id = (data.get("razorpay_order_id") or "").strip()
        payment_id = (data.get("razorpay_payment_id") or "").strip()
        signature = (data.get("razorpay_signature") or "").strip()
        artwork_id = data.get("artwork_id")

        if not order_id or not payment_id or not signature:
            return jsonify({"error": "Missing Razorpay fields"}), 400
        if artwork_id is None:
            return jsonify({"error": "artwork_id is required"}), 400
        try:
            artwork_id = int(artwork_id)
        except Exception:
            return jsonify({"error": "artwork_id must be an integer"}), 400

        result = record_successful_acquisition(
            artwork_id=artwork_id,
            order_id=order_id,
            payment_id=payment_id,
            signature=signature,
        )
        if not result.get("ok"):
            return jsonify({"success": False, "reason": result.get("reason")}), 400

        return jsonify({
            "success": True,
            "message": "Acquisition recorded. Provenance updated.",
            "provenance_updated": True,
            **result,
        })

    except Exception as exc:
        log.error("payments_verify_payment error: %s", exc)
        return jsonify({"error": "Payment verification failed", "detail": str(exc)}), 500

ADMIN_KEY = os.getenv("ADMIN_KEY")
if not ADMIN_KEY:
    raise RuntimeError(
        "ADMIN_KEY environment variable is not set.\n"
        "Generate one: python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "Then set it in Railway -> Variables (or your .env file)."
    )

# ── Startup ───────────────────────────────────────────────────────────────────
def _run_startup_step(step_name: str, fn) -> None:
    try:
        fn()
    except Exception as exc:
        if is_production_deployment():
            log.exception("%s failed during startup.", step_name)
            raise
        log.exception(
            "%s failed during startup; continuing in development mode. Reason: %s",
            step_name,
            exc,
        )


_run_startup_step("db_migrations.run_migrations()", db_migrations.run_migrations)
_run_startup_step("init_db()", init_db)
_run_startup_step("init_did_db()", init_did_db)


def _init_sqlalchemy_models() -> None:
    with app.app_context():
        db.create_all()
        _seed_x402_artwork()


_run_startup_step("db.create_all() / _seed_x402_artwork()", _init_sqlalchemy_models)


# ── Image normalisation helper ────────────────────────────────────────────────

def normalize_and_hash(file_bytes: bytes) -> str:
    img  = Image.open(io.BytesIO(file_bytes))
    exif = img.getexif()
    exif.clear()
    img    = img.convert("RGB")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return hashlib.sha256(buffer.getvalue()).hexdigest()


def compute_binary_integrity_hash(file_bytes: bytes) -> str:
    """SHA-256 over the exact uploaded bytes, preserving tamper evidence."""
    return hashlib.sha256(file_bytes).hexdigest()


# ── Artwork object API (provenance-first) ─────────────────────────────────────

@app.route("/api/artworks/<int:artwork_id>", methods=["GET"])
@limiter.limit("120 per minute")
def get_artwork_object(artwork_id: int):
    try:
        conn = get_db_connection()
        cur = dict_cursor(conn)
        try:
            cur.execute("SELECT * FROM artworks WHERE id = %s", (artwork_id,))
            art = cur.fetchone()
            if not art:
                return jsonify({"error": "Artwork not found"}), 404
            art = dict(art)

            cur.execute(
                """
                SELECT id, artwork_id, provenance_event_type, event_type, event_json, created_at
                FROM artwork_provenance_events
                WHERE artwork_id = %s
                ORDER BY id ASC
                """,
                (artwork_id,),
            )
            events = [dict(r) for r in cur.fetchall()]

            cur.execute(
                """
                SELECT artwork_id, acquisition_id, owner_name, owner_email, collector_reference_id, updated_at
                FROM artwork_ownership
                WHERE artwork_id = %s
                """,
                (artwork_id,),
            )
            own = cur.fetchone()
            ownership = dict(own) if own else None
        finally:
            cur.close()
            conn.close()

        return jsonify(
            {
                "artwork": {
                    "id": art.get("id"),
                    "title": art.get("title"),
                    "description": art.get("description"),
                    "materials": art.get("materials"),
                    "artisan_did": art.get("artisan_did"),
                    "ipfs_cid": art.get("ipfs_cid"),
                    "tx_id": art.get("tx_id"),
                    "status": art.get("status"),
                    "created_at": art.get("created_at"),
                },
                "provenance_events": events,
                "ownership": ownership,
            }
        )
    except Exception as exc:
        log.error("get_artwork_object error: %s", exc)
        return jsonify({"error": "Could not resolve artwork object", "detail": str(exc)}), 500


# ── Wallet readiness check ────────────────────────────────────────────────────

def is_wallet_ready(address: str) -> bool:
    """
    Return True if the institution wallet has at least 200,000 microAlgos.
    An Algorand account below this threshold cannot submit transactions.
    """
    try:
        client = get_algod_client()
        info   = client.account_info(address)
        return info.get("amount", 0) >= 200_000
    except Exception as exc:
        log.warning("Wallet readiness check failed for %s: %s", address, exc)
        return False


# ── Institution wallet info ───────────────────────────────────────────────────

@app.route("/institution/wallet", methods=["GET"])
def institution_wallet():
    """
    Return the authenticated institution's Algorand wallet address and live
    funding status. Private keys are never returned.
    """
    try:
        api_key     = request.headers.get("X-API-Key")
        institution = validate_api_key(api_key)
        if not institution:
            return jsonify({"error": "Invalid or missing API key"}), 401

        address = institution.get("address") or institution.get("institution_address")
        if not address:
            return jsonify({
                "error": "No wallet found for this institution. Contact your admin."
            }), 404

        funded  = is_wallet_ready(address)
        balance = None
        try:
            info    = get_algod_client().account_info(address)
            balance = info.get("amount", 0)          # microAlgos
        except Exception as exc:
            log.warning("Balance fetch failed for %s: %s", address, exc)

        return jsonify({
            "wallet_address":    address,
            "funded":            funded,
            "balance_microalgo": balance,
            "balance_algo":      round(balance / 1_000_000, 6) if balance is not None else None,
            "min_required_algo": 0.2,
            "network":           "algorand-testnet",
            "faucet_url":        "https://bank.testnet.algorand.network/",
        })

    except Exception as exc:
        log.error("institution_wallet error: %s", exc)
        return jsonify({"error": "Could not fetch wallet info"}), 500


# ── Batch issuance ────────────────────────────────────────────────────────────

@app.route("/issue/batch", methods=["POST"])
def issue_batch():
    try:
        api_key     = request.headers.get("X-API-Key")
        institution = validate_api_key(api_key)
        if not institution:
            return jsonify({"error": "Invalid or missing API key"}), 401

        doc_type = request.form.get("doc_type", "academic")

        inst_id = (
            institution.get("institution_id")
            if institution.get("wallet_version", 1) == 2
            else None
        )

        inst_address = institution.get("address") or institution.get("institution_address")
        if inst_address and not is_wallet_ready(inst_address):
            return jsonify({"error": "Institution wallet not funded"}), 400

        batch_id = secrets.token_hex(8)
        jobs     = []

        # Priority: explicit multi-file upload > ZIP fallback
        direct_files = request.files.getlist("files")
        zip_file     = request.files.get("certificates")

        if direct_files:
            if len(direct_files) > 500:
                return jsonify({"error": "Max 500 per batch"}), 400

            ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".pdf"}

            for upload in direct_files:
                filename = upload.filename or ""
                ext      = os.path.splitext(filename)[1].lower()

                if ext not in ALLOWED_EXTENSIONS:
                    jobs.append({
                        "filename": filename,
                        "error":    f"Unsupported file type: {ext}",
                        "status":   "skipped",
                    })
                    continue

                try:
                    file_bytes  = upload.read()
                    cert_hash   = normalize_and_hash(file_bytes)
                    integrity_hash = compute_binary_integrity_hash(file_bytes)
                    del file_bytes

                    signature   = sign_credential(cert_hash, institution_id=inst_id)

                    basename    = os.path.splitext(os.path.basename(filename))[0]
                    cert_number = basename

                    jobs.append({
                        "cert_hash":   cert_hash,
                        "signature":   signature,
                        "filename":    filename,
                        "doc_type":    doc_type,
                        "cert_number": cert_number,
                        "issued_to":   None,
                        "integrity_hash": integrity_hash,
                    })

                except Exception as e:
                    log.warning("Skipping %s in direct batch: %s", filename, e)
                    jobs.append({
                        "filename": filename,
                        "error":    str(e),
                        "status":   "hash_failed",
                    })

        elif zip_file:
            with zipfile.ZipFile(zip_file) as zf:
                cert_meta: dict = {}
                if "metadata.json" in zf.namelist():
                    try:
                        cert_meta = _json.loads(zf.read("metadata.json").decode())
                    except Exception as exc:
                        log.warning("metadata.json in ZIP is malformed: %s", exc)

                cert_files = [
                    f for f in zf.namelist()
                    if f.endswith((".png", ".jpg", ".jpeg", ".pdf"))
                    and not f.startswith("__MACOSX")
                ]

                if len(cert_files) > 500:
                    return jsonify({"error": "Max 500 per batch"}), 400

                for filename in cert_files:
                    try:
                        file_bytes = zf.read(filename)
                        cert_hash  = normalize_and_hash(file_bytes)
                        integrity_hash = compute_binary_integrity_hash(file_bytes)
                        del file_bytes

                        signature = sign_credential(cert_hash, institution_id=inst_id)

                        meta        = cert_meta.get(filename, {})
                        basename    = os.path.splitext(os.path.basename(filename))[0]
                        cert_number = meta.get("cert_number") or basename

                        issued_to_name = meta.get("issued_to_name", "")
                        issued_to_hash = (
                            hashlib.sha256(issued_to_name.strip().lower().encode()).hexdigest()
                            if issued_to_name
                            else None
                        )

                        jobs.append({
                            "cert_hash":   cert_hash,
                            "signature":   signature,
                            "filename":    filename,
                            "doc_type":    doc_type,
                            "cert_number": cert_number,
                            "issued_to":   issued_to_hash,
                            "integrity_hash": integrity_hash,
                        })
                    except Exception as e:
                        jobs.append({
                            "filename": filename,
                            "error":    str(e),
                            "status":   "hash_failed",
                        })

        else:
            return jsonify({
                "error": "No files uploaded. Use 'files' (multi-file) or 'certificates' (ZIP)."
            }), 400

        if not jobs:
            return jsonify({"error": "No valid files found in the upload"}), 400

        queue_batch(batch_id, jobs, institution)

        return jsonify({
            "batch_id":       batch_id,
            "queued":         len([j for j in jobs if "cert_hash" in j]),
            "failed_at_hash": len([j for j in jobs if "error" in j]),
            "status_url":     f"/batch/status/{batch_id}",
            "message":        "Certificates hashed and queued for Algorand anchoring",
            "upload_mode":    "direct" if direct_files else "zip",
        })

    except Exception as exc:
        log.error("issue_batch error: %s", exc)
        return jsonify({"error": "Batch issuance failed", "detail": str(exc)}), 500


@app.route("/batch/status/<batch_id>", methods=["GET"])
def batch_status(batch_id):
    try:
        api_key = request.headers.get("X-API-Key")
        if not validate_api_key(api_key):
            return jsonify({"error": "Unauthorized"}), 403
        return jsonify(get_batch_status(batch_id))
    except Exception as exc:
        log.error("batch_status error: %s", exc)
        return jsonify({"error": "Could not fetch batch status"}), 500


# ── DigiLocker ────────────────────────────────────────────────────────────────

@app.route("/digilocker/start", methods=["POST"])
def digilocker_start():
    try:
        body         = request.json or {}
        redirect_url = body.get(
            "redirect_url", request.url_root + "digilocker/callback"
        )
        user_name = body.get("name", "").strip()

        if not user_name:
            return jsonify({"error": "name is required to start a DigiLocker session"}), 400

        result = create_digilocker_request(redirect_url, user_name)
        result["digilocker_url"] = f"/kyc-consent?id={result['request_id']}"
        return jsonify(result)
    except Exception as exc:
        log.error("digilocker_start error: %s", exc)
        return jsonify({"error": "Could not start DigiLocker session"}), 500


@app.route("/kyc-consent", methods=["GET"])
def kyc_consent():
    req_id = request.args.get("id", "")
    from flask import render_template_string
    return render_template_string("""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>DigiLocker Consent</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:sans-serif;background:#1a237e;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:white;border-radius:16px;width:360px;overflow:hidden}.header{background:#1a237e;padding:20px 24px;color:white}.logo{font-size:12px;opacity:.7;margin-bottom:4px}.title{font-size:18px;font-weight:600}.body{padding:20px 24px}.app{display:flex;align-items:center;gap:12px;background:#f8f9ff;border:1px solid #e8eaf6;border-radius:10px;padding:12px;margin-bottom:16px}.icon{width:40px;height:40px;background:#1a237e;border-radius:8px;display:flex;align-items:center;justify-content:center;color:white;font-size:18px;font-weight:700}.name{font-size:14px;font-weight:600}.desc{font-size:12px;color:#666;margin-top:2px}.item{display:flex;align-items:flex-start;gap:8px;margin-bottom:8px;font-size:13px;color:#555}.item::before{content:"checkmark";color:#0f6e56;font-weight:700;margin-top:1px;flex-shrink:0}.footer{padding:0 24px 20px;display:flex;gap:10px}.deny{flex:1;padding:10px;font-size:13px;font-weight:500;background:white;border:1px solid #ddd;border-radius:8px;cursor:pointer}.allow{flex:2;padding:10px;font-size:13px;font-weight:500;background:#1a237e;color:white;border:none;border-radius:8px;cursor:pointer}</style>
</head><body><div class="card">
<div class="header"><div class="logo">DigiLocker - Powered by MeitY</div><div class="title">Consent Request</div></div>
<div class="body">
<div class="app"><div class="icon">S</div><div><div class="name">SkillChain</div><div class="desc">Credential verification platform</div></div></div>
<div style="font-size:13px;font-weight:600;margin-bottom:10px">SkillChain is requesting:</div>
<div class="item">Your Aadhaar-verified name</div>
<div class="item">Your DigiLocker user ID</div>
<div class="item">Identity proof for credential binding</div>
<div style="font-size:11px;color:#999;margin-top:12px;line-height:1.6">Documents will NOT be shared. Only verified identity is used.</div>
</div>
<div class="footer">
<button class="deny" onclick="window.close()">Deny</button>
<button class="allow" onclick="allow()">Allow Access</button>
</div></div>
<script>
function allow() {
  document.querySelector('.allow').textContent = 'Verifying...';
  document.querySelector('.allow').disabled = true;
  fetch('/digilocker/callback?id={{ req_id }}')
    .then(() => { window.location.href = '/?id={{ req_id }}'; })
    .catch(() => { window.location.href = '/?id={{ req_id }}'; });
}
</script></body></html>""", req_id=req_id)


@app.route("/digilocker/callback", methods=["GET"])
def digilocker_callback():
    try:
        request_id = request.args.get("id")
        if not request_id:
            return jsonify({"error": "Missing request id"}), 400

        status = get_request_status(request_id)

        if status["status"] == "not_found":
            from digilocker_service import ensure_mock_session
            status = ensure_mock_session(request_id)

        if status["status"] != "authenticated":
            return jsonify({"error": "User has not consented yet"}), 403

        return jsonify({
            "success":    True,
            "request_id": request_id,
            "user":       status["user"],
            "message":    "Consent received. Call POST /digilocker/verify with this request_id to bind your identity.",
        })
    except Exception as exc:
        log.error("digilocker_callback error: %s", exc)
        return jsonify({"error": "DigiLocker callback failed"}), 500


@app.route("/digilocker/bind", methods=["POST"])
@limiter.limit("20 per minute")
def digilocker_bind():
    try:
        data            = request.get_json()
        digilocker_id   = data.get("digilocker_id")
        digilocker_name = data.get("digilocker_name")

        if not digilocker_id or not digilocker_name:
            return jsonify({"error": "digilocker_id and digilocker_name are required"}), 400

        anchor = bind_identity(digilocker_id, digilocker_name)
        return jsonify({
            "success":      True,
            "identity_did": anchor["identity_did"],
            "created":      anchor["created"],
            "message":      (
                "Identity anchor created"
                if anchor["created"]
                else "Existing identity anchor returned"
            ),
        })
    except Exception as exc:
        log.error("Identity bind failed: %s", exc)
        return jsonify({"error": "Identity binding failed"}), 500


@app.route("/digilocker/identity/<digilocker_id>", methods=["GET"])
@limiter.limit("30 per minute")
def digilocker_get_identity(digilocker_id: str):
    try:
        api_key = request.headers.get("X-API-Key")
        if not validate_api_key(api_key):
            return jsonify({"error": "Unauthorized"}), 401

        anchor = lookup_identity(digilocker_id)
        if not anchor:
            return jsonify({"error": "No identity anchor found for this DigiLocker ID"}), 404

        return jsonify({
            "identity_did": anchor["identity_did"],
            "bound_at":     anchor["bound_at"],
        })
    except Exception as exc:
        log.error("digilocker_get_identity error: %s", exc)
        return jsonify({"error": "Identity lookup failed"}), 500


@app.route("/digilocker/verify", methods=["POST"])
@limiter.limit("20 per minute")
def digilocker_verify():
    try:
        data       = request.get_json() or {}
        request_id = data.get("request_id")

        if not request_id:
            return jsonify({"error": "request_id is required"}), 400

        result = verify_with_identity(request_id)

        if not result.get("success"):
            return jsonify(result), 422

        return jsonify(result), 200
    except Exception as exc:
        log.error("digilocker_verify error: %s", exc)
        return jsonify({"error": "DigiLocker verification failed"}), 500


# ── Core routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return jsonify({
        "service":"SkillChain API",
        "status":"online",
        "frontend": frontend_url
    })


@app.route("/issue", methods=["POST"])
@limiter.limit("10 per minute")
def issue():
    try:
        api_key     = request.headers.get("X-API-Key")
        institution = validate_api_key(api_key)
        if not institution:
            return jsonify({"error": "Invalid or missing API key"}), 401

        if "certificate" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        file = request.files["certificate"]
        if file.filename == "":
            return jsonify({"error": "Empty filename"}), 400

        inst_address = institution.get("address") or institution.get("institution_address")
        if inst_address and not is_wallet_ready(inst_address):
            return jsonify({"error": "Institution wallet not funded"}), 400

        doc_type       = request.form.get("doc_type", "academic")
        cert_number    = request.form.get("cert_number")
        issued_to_name = request.form.get("issued_to_name")
        issued_to_hash = (
            hashlib.sha256(issued_to_name.strip().lower().encode()).hexdigest()
            if issued_to_name
            else None
        )

        file_bytes = file.read()
        cert_hash  = normalize_and_hash(file_bytes)
        integrity_hash = compute_binary_integrity_hash(file_bytes)
        del file_bytes

        inst_id = (
            institution.get("institution_id")
            if institution.get("wallet_version", 1) == 2
            else None
        )

        signature = sign_credential(cert_hash, institution_id=inst_id)
        result    = anchor_hash(
            cert_hash, doc_type, institution, signature,
            institution_id=inst_id,
            cert_number=cert_number,
            issued_to=issued_to_hash,
            integrity_hash=integrity_hash,
        )

        return jsonify({
            "success":        True,
            "cert_hash":      cert_hash,
            "integrity_hash": integrity_hash,
            "tx_id":          result["tx_id"],
            "ipfs_cid":       result.get("ipfs_cid"),
            "wallet_version": result.get("wallet_version", 1),
            "artisan":        institution["institution"],
            "artisan_did":    institution.get("did", ""),
            "explorer_url":   f"https://testnet.explorer.perawallet.app/tx/{result['tx_id']}",
        })

    except Exception as exc:
        log.error("issue error: %s", exc)
        return jsonify({"error": "Certificate issuance failed", "detail": str(exc)}), 500


@app.route("/verify", methods=["POST"])
@limiter.limit("30 per minute")
def verify():
    try:
        if "certificate" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["certificate"]
        if file.filename == "":
            return jsonify({"error": "Empty filename"}), 400

        file_bytes = file.read()
        cert_hash  = normalize_and_hash(file_bytes)
        integrity_hash = compute_binary_integrity_hash(file_bytes)
        return jsonify(verify_hash(cert_hash, uploaded_integrity_hash=integrity_hash))

    except Exception as exc:
        log.error("verify error: %s", exc)
        return jsonify({"error": "Verification failed", "detail": str(exc)}), 500


# ── Registration flow ─────────────────────────────────────────────────────────

@app.route("/request-registration", methods=["POST"])
def request_reg():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "JSON body required"}), 400

        required = ["institution_name", "email", "domain"]
        if not all(k in data for k in required):
            return jsonify({"error": "institution_name, email, domain required"}), 400

        result = request_registration(
            data["institution_name"], data["email"], data["domain"]
        )

        status_code = result.pop("http_status", 200)

        # FIX (Flaw 3): Rewrite verify_url to match the current deployment host.
        # did_service may hardcode localhost — this patch makes it environment-aware
        # so the link works identically on Railway, Render, or localhost.
        if result.get("verify_url"):
            result["verify_url"] = re.sub(
                r'^https?://[^/]+',
                request.url_root.rstrip('/'),
                result["verify_url"],
            )

        return jsonify(result), status_code

    except Exception as exc:
        log.error("request_reg error: %s", exc)
        return jsonify({"error": "Registration request failed", "detail": str(exc)}), 500


@app.route("/verify-email", methods=["GET"])
def verify_email():
    try:
        token = request.args.get("token")
        if not token:
            return jsonify({"error": "Token required"}), 400
        result = verify_email_token(token)
        status = 200 if result.get("success") else 400
        return jsonify(result), status
    except Exception as exc:
        log.error("verify_email error: %s", exc)
        return jsonify({"error": "Email verification failed"}), 500


# ── Admin routes ──────────────────────────────────────────────────────────────

@app.route("/admin/pending", methods=["GET"])
def admin_pending():
    try:
        if request.headers.get("X-Admin-Key") != ADMIN_KEY:
            return jsonify({"error": "Unauthorized"}), 403
        return jsonify(get_pending_registrations())
    except Exception as exc:
        log.error("admin_pending error: %s", exc)
        return jsonify({"error": "Could not fetch pending registrations"}), 500


@app.route("/admin/approve/<registration_id>", methods=["POST"])
def admin_approve(registration_id):
    try:
        if request.headers.get("X-Admin-Key") != ADMIN_KEY:
            return jsonify({"error": "Unauthorized"}), 403

        result = approve_registration(registration_id)

        status_code = result.pop("http_status", 200)
        return jsonify(result), status_code

    except Exception as exc:
        log.error("admin_approve error for %s: %s", registration_id, exc)
        return jsonify({"error": "Approval failed", "detail": str(exc)}), 500


@app.route("/admin/revoke-issuer/<institution_id>", methods=["POST"])
def admin_revoke_issuer(institution_id):
    try:
        if request.headers.get("X-Admin-Key") != ADMIN_KEY:
            return jsonify({"error": "Unauthorized"}), 403

        data   = request.get_json(silent=True) or {}
        reason = data.get("reason", "")

        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute(
            """
            UPDATE did_registry
            SET revoked        = 1,
                revoked_at     = %s,
                revoked_reason = %s
            WHERE institution_id = %s
            """,
            (time.strftime("%Y-%m-%dT%H:%M:%SZ"), reason, institution_id),
        )
        conn.commit()
        rows_affected = cur.rowcount
        cur.close()
        conn.close()

        if rows_affected == 0:
            return jsonify({"error": f"No institution found with id '{institution_id}'"}), 404

        log.warning("Institution revoked: institution_id=%s reason=%r", institution_id, reason)
        return jsonify({
            "success":        True,
            "institution_id": institution_id,
            "revoked_at":     time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "reason":         reason,
        })

    except Exception as exc:
        log.error("admin_revoke_issuer error: %s", exc)
        return jsonify({"error": "Revocation failed", "detail": str(exc)}), 500


# ── Artisan-first routes ────────────────────────────────────────────────

def _derive_artisan_id(name: str) -> str:
    """
    Derive a stable, URL-safe artisan_id from the artisan's name.
    Format: 'artisan/<16-char-hex>'
    The 'artisan/' prefix is used throughout the signing and Vault routing
    layers to distinguish artisan keys from institution keys.
    Vault path: secret/skillchain/artisan/<16-char-hex>
    """
    import hashlib
    suffix = hashlib.sha256(name.strip().lower().encode()).hexdigest()[:16]
    return f"artisan/{suffix}"


def _demo_mode_enabled() -> bool:
    return os.getenv("DEMO_MODE", "false").lower() == "true"


def _get_demo_treasury_private_key() -> str:
    phrase = os.getenv("MNEMONIC")
    if not phrase:
        raise RuntimeError(
            "DEMO_MODE requires the existing MNEMONIC env var for treasury funding."
        )
    from algosdk import mnemonic as _mn
    return _mn.to_private_key(phrase)


def _wallet_balance_microalgos(address: str) -> int:
    client = get_algod_client()
    info = client.account_info(address)
    return int(info.get("amount", 0))


def _build_artisan_signing_key(artisan_id: str, *, reuse_identity: bool):
    from nacl.encoding import RawEncoder as _Raw
    from nacl.signing import SigningKey as _NaClSK

    if reuse_identity and _demo_mode_enabled():
        phrase = os.getenv("MNEMONIC")
        if not phrase:
            raise RuntimeError(
                "DEMO_MODE reusable artisan identities require the existing MNEMONIC env var."
            )
        deterministic_seed = hashlib.sha256(
            f"skillchain:demo-artisan:{artisan_id}:{phrase}".encode()
        ).digest()
        log.info(
            "Using deterministic DEMO_MODE artisan identity for %s",
            artisan_id,
        )
        return _NaClSK(deterministic_seed, encoder=_Raw)

    return _NaClSK.generate()


def _fund_demo_artisan_wallet_if_needed(
    recipient_wallet: str,
    *,
    minimum_balance_microalgos: int = 500_000,
) -> tuple[str | None, int, int]:
    """
    In DEMO_MODE, bootstrap an artisan wallet from the existing treasury mnemonic.

    Returns:
        (funding_tx_id, funded_amount, current_balance)
    """
    client = get_algod_client()
    current_balance = _wallet_balance_microalgos(recipient_wallet)
    if current_balance >= minimum_balance_microalgos:
        log.info(
            "Skipping DEMO_MODE artisan funding; wallet already funded | recipient=%s balance=%s threshold=%s",
            recipient_wallet,
            current_balance,
            minimum_balance_microalgos,
        )
        return None, 0, current_balance

    treasury_private_key = _get_demo_treasury_private_key()
    from algosdk import account as _account

    sender_wallet = _account.address_from_private_key(treasury_private_key)
    treasury_balance = _wallet_balance_microalgos(sender_wallet)
    funded_amount = minimum_balance_microalgos - current_balance
    required_balance = funded_amount + 200_000
    if treasury_balance < required_balance:
        raise RuntimeError(
            f"DEMO treasury balance too low: {treasury_balance} microAlgos; "
            f"need at least {required_balance} to fund {recipient_wallet}."
        )

    params = client.suggested_params()
    fund_txn = algo_txn_mod.PaymentTxn(
        sender=sender_wallet,
        sp=params,
        receiver=recipient_wallet,
        amt=funded_amount,
        note=b"skillchain:demo-artisan-bootstrap",
    )
    signed_txn = fund_txn.sign(treasury_private_key)
    tx_id = client.send_transaction(signed_txn)
    wait_for_confirmation(client, tx_id, 4)
    log.info(
        "DEMO_MODE artisan wallet funded | tx_id=%s amount_microalgos=%s sender=%s recipient=%s",
        tx_id,
        funded_amount,
        sender_wallet,
        recipient_wallet,
    )
    return tx_id, funded_amount, current_balance + funded_amount


@app.route("/register-artisan", methods=["POST"])
@limiter.limit("20 per minute")
def register_artisan():
    """
    Stage 1 of artisan onboarding: store a pending artisan record.
    No DID, keys, or wallet are generated at this stage.
    The artisan must be approved by an admin before identity is created.
    """
    try:
        data = request.get_json() or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name is required"}), 400

        craft_type = (data.get("craft_type") or "").strip()
        cluster    = (data.get("cluster")    or "").strip()
        location   = (data.get("location")   or "").strip()

        artisan_id = _derive_artisan_id(name)
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        conn = get_db_connection()
        cur  = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO artisans
                    (artisan_id, name, craft_type, cluster, location, status, created_at)
                VALUES (%s, %s, %s, %s, %s, 'pending', %s)
                ON CONFLICT (artisan_id) DO NOTHING
                """,
                (artisan_id, name, craft_type, cluster, location, created_at),
            )
            conn.commit()
            inserted = cur.rowcount
        finally:
            cur.close()
            conn.close()

        if inserted == 0:
            return jsonify({"error": "An artisan with this name already exists"}), 409

        # Fetch the assigned DB id
        conn2 = get_db_connection()
        cur2  = dict_cursor(conn2)
        try:
            cur2.execute(
                "SELECT id FROM artisans WHERE artisan_id = %s",
                (artisan_id,),
            )
            row = cur2.fetchone()
        finally:
            cur2.close()
            conn2.close()

        return jsonify({
            "success":    True,
            "id":         row["id"] if row else None,
            "artisan_id": artisan_id,
            "name":       name,
            "status":     "pending",
            "created_at": created_at,
            "message":    "Artisan registered. Awaiting admin approval before identity is created.",
        }), 201

    except Exception as exc:
        log.error("register_artisan error: %s", exc)
        return jsonify({"error": "Artisan registration failed", "detail": str(exc)}), 500
    
@app.route("/debug/artisans")
def debug_artisans():
    conn = get_db_connection()
    cur = dict_cursor(conn)

    try:
        cur.execute("""
            SELECT id, artisan_id, name, status, did, created_at
            FROM artisans
            ORDER BY created_at DESC
            LIMIT 20
        """)

        rows = [dict(r) for r in cur.fetchall()]

        return jsonify(rows)

    finally:
        cur.close()
        conn.close()


@app.route("/admin/artisans/pending", methods=["GET"])
def admin_artisans_pending():
    """List all artisans with status = pending. Requires X-Admin-Key."""
    try:
        if request.headers.get("X-Admin-Key") != ADMIN_KEY:
            return jsonify({"error": "Unauthorized"}), 403

        conn = get_db_connection()
        cur  = dict_cursor(conn)
        try:
            cur.execute(
                """
                SELECT id, artisan_id, name, craft_type, cluster, location, created_at
                FROM artisans WHERE status = 'pending'
                ORDER BY created_at DESC
                """
            )
            rows = [dict(r) for r in cur.fetchall()]
        finally:
            cur.close()
            conn.close()

        return jsonify(rows)

    except Exception as exc:
        log.error("admin_artisans_pending error: %s", exc)
        return jsonify({"error": "Could not fetch pending artisans"}), 500


@app.route("/admin/approve-artisan/<int:artisan_db_id>", methods=["POST"])
def admin_approve_artisan(artisan_db_id: int):
    """
    Stage 2 of artisan onboarding: generate identity & approve.

    This is the ONLY place where:
      - Ed25519 keypair is generated
      - Algorand wallet address is derived
      - DID is created
      - Private key is written to Vault (or AES-GCM in dev mode)

    Vault path: secret/skillchain/artisan/<artisan_id_suffix>
    Private key is also stored temporarily in artisans.enc_private_key
    (AES-GCM, same format as did_registry) as deprecated fallback.
    """
    try:
        if request.headers.get("X-Admin-Key") != ADMIN_KEY:
            return jsonify({"error": "Unauthorized"}), 403

        payload = request.get_json(silent=True) or {}
        reuse_identity = payload.get("reuse_identity")
        if reuse_identity is None:
            reuse_identity = _demo_mode_enabled()
        else:
            reuse_identity = bool(reuse_identity)

        # Fetch pending artisan
        conn = get_db_connection()
        cur  = dict_cursor(conn)
        try:
            cur.execute(
                "SELECT * FROM artisans WHERE id = %s AND status = 'pending'",
                (artisan_db_id,),
            )
            artisan = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if not artisan:
            return jsonify({"error": "Artisan not found or already processed"}), 404

        artisan      = dict(artisan)
        artisan_id   = artisan["artisan_id"]   # e.g. 'artisan/8f3a1c9d24b07e5f'
        artisan_name = artisan["name"]

        # ── Generate Ed25519 keypair + Algorand address ───────────────────
        from nacl.encoding import RawEncoder as _Raw
        from algosdk import encoding as _ae
        import base64 as _b64

        signing_key      = _build_artisan_signing_key(
            artisan_id,
            reuse_identity=reuse_identity,
        )
        seed_bytes       = signing_key.encode(encoder=_Raw)              # 32 bytes
        pub_bytes        = signing_key.verify_key.encode(encoder=_Raw)   # 32 bytes
        private_key_bytes = seed_bytes + pub_bytes                        # 64 bytes
        algorand_wallet  = _ae.encode_address(pub_bytes)
        ed25519_pubkey   = _b64.b64encode(pub_bytes).decode()

        # DID follows same pattern as institutions: did:algo:testnet:<address>:<suffix>
        id_suffix = artisan_id.split("/", 1)[1]  # strip 'artisan/' prefix
        artisan_did = f"did:algo:testnet:{algorand_wallet}:{id_suffix}"

        # ── Store key (Vault primary, AES-GCM fallback) ─────────────────
        enc_private_key: str | None = None
        key_nonce:       str | None = None

        try:
            from vault_client import is_vault_enabled
            if is_vault_enabled():
                from vault_client import write_key
                write_key(artisan_id, private_key_bytes)
                log.info("Vault write confirmed for artisan_id=%s", artisan_id)
            else:
                from key_vault import encrypt_key
                enc_private_key, key_nonce = encrypt_key(private_key_bytes)
        finally:
            # Best-effort memory minimisation
            del private_key_bytes
            del seed_bytes
            del pub_bytes
            del signing_key

        funding_tx_id = None
        funding_amount_microalgos = 0
        funding_status = "not_requested"
        if _demo_mode_enabled():
            funding_status = "already_funded"
            funding_tx_id, funding_amount_microalgos, _ = _fund_demo_artisan_wallet_if_needed(
                algorand_wallet,
            )
            if funding_tx_id:
                funding_status = "funded"
            log.info(
                "DEMO_MODE artisan bootstrap complete | artisan_id=%s wallet=%s funding_status=%s funding_tx_id=%s funded_amount=%s",
                artisan_id,
                algorand_wallet,
                funding_status,
                funding_tx_id,
                funding_amount_microalgos,
            )

        approved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        approved_by = request.headers.get("X-Approved-By", "admin")

        # ── Persist approved artisan ───────────────────────────
        conn = get_db_connection()
        cur  = conn.cursor()
        try:
            cur.execute(
                """
                UPDATE artisans
                SET did             = %s,
                    algorand_wallet = %s,
                    ed25519_pubkey  = %s,
                    enc_private_key = %s,
                    key_nonce       = %s,
                    status          = 'approved',
                    approved_by     = %s,
                    approved_at     = %s
                WHERE id = %s
                """,
                (
                    artisan_did, algorand_wallet, ed25519_pubkey,
                    enc_private_key, key_nonce,
                    approved_by, approved_at, artisan_db_id,
                ),
            )
            conn.commit()
        finally:
            cur.close()
            conn.close()

        log.info(
            "Artisan approved: id=%s artisan_id=%s did=%s wallet=%s",
            artisan_db_id, artisan_id, artisan_did, algorand_wallet,
        )
        return jsonify({
            "success":        True,
            "id":             artisan_db_id,
            "artisan_id":     artisan_id,
            "did":            artisan_did,
            "algorand_wallet": algorand_wallet,
            "ed25519_pubkey": ed25519_pubkey,
            "reuse_identity": reuse_identity,
            "status":         "approved",
            "approved_by":    approved_by,
            "approved_at":    approved_at,
            "funding_tx_id":  funding_tx_id,
            "funding_status": funding_status,
            "funded_amount_microalgos": funding_amount_microalgos,
            "vault_path":     f"secret/skillchain/{artisan_id}",
            "message":        "Artisan identity created. Keys stored in Vault (or AES-GCM fallback).",
        })

    except Exception as exc:
        log.error("admin_approve_artisan error for id=%s: %s", artisan_db_id, exc)
        return jsonify({"error": "Artisan approval failed", "detail": str(exc)}), 500


@app.route("/admin/reject-artisan/<int:artisan_db_id>", methods=["POST"])
def admin_reject_artisan(artisan_db_id: int):
    """Reject a pending artisan application. Requires X-Admin-Key."""
    try:
        if request.headers.get("X-Admin-Key") != ADMIN_KEY:
            return jsonify({"error": "Unauthorized"}), 403

        data   = request.get_json(silent=True) or {}
        reason = data.get("reason", "")

        conn = get_db_connection()
        cur  = conn.cursor()
        try:
            cur.execute(
                """
                UPDATE artisans
                SET status      = 'rejected',
                    approved_by = %s,
                    approved_at = %s
                WHERE id = %s AND status = 'pending'
                """,
                (request.headers.get("X-Approved-By", "admin"),
                 time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 artisan_db_id),
            )
            conn.commit()
            rows = cur.rowcount
        finally:
            cur.close()
            conn.close()

        if rows == 0:
            return jsonify({"error": "Artisan not found or not in pending state"}), 404

        return jsonify({
            "success":  True,
            "id":       artisan_db_id,
            "status":   "rejected",
            "reason":   reason,
        })

    except Exception as exc:
        log.error("admin_reject_artisan error: %s", exc)
        return jsonify({"error": "Rejection failed", "detail": str(exc)}), 500


@app.route("/add-artwork", methods=["POST"])
@limiter.limit("10 per minute")
def add_artwork():
    """
    Register an artwork for an approved artisan.

    Multipart form fields:
      - artwork      : image file (multipart)
      - artisan_did  : the artisan's DID string
      - title        : artwork title
      - description  : optional description
      - materials    : comma-separated materials list

    Flow:
      1. Validate artisan is approved
      2. Normalize image + compute SHA-256 hash
      3. Sign hash with artisan's Ed25519 key
      4. Pin artisan-format metadata to IPFS
      5. Anchor on Algorand using artisan's wallet
      6. Write artwork record to DB
    """
    try:
        artisan_did = (request.form.get("artisan_did") or "").strip()
        if not artisan_did:
            return jsonify({"error": "artisan_did is required"}), 400

        if "artwork" not in request.files:
            return jsonify({"error": "No artwork file uploaded (field: 'artwork')"}), 400

        file = request.files["artwork"]
        if not file.filename:
            return jsonify({"error": "Empty filename"}), 400

        # ── Look up artisan ───────────────────────────────────
        conn = get_db_connection()
        cur  = dict_cursor(conn)
        try:
            cur.execute(
                """
                SELECT id, artisan_id, name, algorand_wallet, status
                FROM artisans WHERE did = %s
                """,
                (artisan_did,),
            )
            artisan = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if not artisan:
            return jsonify({"error": "Artisan not found for the given DID"}), 404
        artisan = dict(artisan)

        if artisan["status"] != "approved":
            return jsonify({
                "error":  "Artisan is not approved",
                "status": artisan["status"],
            }), 403

        artisan_id_key  = artisan["artisan_id"]    # e.g. 'artisan/8f3a1c9d24b07e5f'
        artisan_wallet  = artisan["algorand_wallet"]
        artisan_name    = artisan["name"]

        title       = (request.form.get("title")       or "").strip()
        description = (request.form.get("description") or "").strip()
        materials   = (request.form.get("materials")   or "").strip()

        # ── Hash the artwork image ────────────────────────────
        file_bytes = file.read()
        cert_hash  = normalize_and_hash(file_bytes)
        integrity_hash = compute_binary_integrity_hash(file_bytes)
        del file_bytes

        # ── Sign with artisan's key ─────────────────────────
        signature  = sign_credential_hash(cert_hash, institution_id=artisan_id_key)

        # ── Build artisan-format IPFS metadata ───────────────
        issued_at  = time.strftime("%Y-%m-%d")
        hmac_val   = generate_hmac(cert_hash)
        metadata   = {
            "version":     "2.0",
            "cert_hash":   cert_hash,
            "artisan_did": artisan_did,
            "artisan":     artisan_name,
            "title":       title,
            "materials":   materials,
            "doc_type":    "artwork",
            "issued_at":   issued_at,
            "signature":   signature,
            "hmac_value":  hmac_val,
            "integrity_hash": integrity_hash,
        }

        # ── Pin to IPFS ──────────────────────────────────
        ipfs_cid = pin_with_retry(metadata)

        # ── Anchor on Algorand (artisan's own wallet as sender) ───
        import json as _j
        client     = get_algod_client()
        note_data  = {"sc": "1", "cid": ipfs_cid, "wv": 2}
        note_bytes = _j.dumps(note_data).encode()
        assert len(note_bytes) < 150, f"Note too large: {len(note_bytes)}"

        params     = client.suggested_params()
        txn        = algo_txn_mod.PaymentTxn(
            sender=artisan_wallet,
            sp=params,
            receiver=artisan_wallet,
            amt=0,
            note=note_bytes,
        )
        signed_txn = sign_transaction(txn, artisan_id_key)
        tx_id      = client.send_transaction(signed_txn)
        wait_for_confirmation(client, tx_id, 4)

        # ── Persist to artworks table ───────────────────────
        conn = get_db_connection()
        cur  = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO artworks
                    (artisan_did, title, description, materials,
                     cert_hash, signature, ipfs_cid, tx_id, status, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'anchored', %s)
                ON CONFLICT (cert_hash) DO NOTHING
                """,
                (artisan_did, title, description, materials,
                 cert_hash, signature, ipfs_cid, tx_id, issued_at),
            )
            conn.commit()
        finally:
            cur.close()
            conn.close()

        # Fetch artwork id (needed for commerce flows)
        artwork_id = None
        conn_id = get_db_connection()
        cur_id = dict_cursor(conn_id)
        try:
            cur_id.execute("SELECT id FROM artworks WHERE cert_hash = %s", (cert_hash,))
            row_id = cur_id.fetchone()
            artwork_id = (row_id["id"] if row_id else None)
        finally:
            cur_id.close()
            conn_id.close()

        # Also write to certificates table so verify_hash() finds it immediately
        save_to_db(cert_hash, tx_id, "artwork", issued_at, ipfs_cid)

        return jsonify({
            "success":      True,
            "artwork_id":   artwork_id,
            "cert_hash":    cert_hash,
            "integrity_hash": integrity_hash,
            "tx_id":        tx_id,
            "ipfs_cid":     ipfs_cid,
            "artisan_did":  artisan_did,
            "artisan":      artisan_name,
            "title":        title,
            "explorer_url": f"https://testnet.explorer.perawallet.app/tx/{tx_id}",
        })

    except Exception as exc:
        log.error("add_artwork error: %s", exc)
        return jsonify({"error": "Artwork registration failed", "detail": str(exc)}), 500


@app.route("/artisan/<path:did>", methods=["GET"])
def resolve_artisan(did: str):
    """
    Resolve an artisan DID to a lightweight public profile.
    Returns approved artisan info; never exposes keys.
    """
    try:
        if not re.match(r"^did:[a-z]+:[a-zA-Z0-9._\-:]+$", did):
            return jsonify({"error": "Invalid DID format"}), 400

        conn = get_db_connection()
        cur  = dict_cursor(conn)
        try:
            cur.execute(
                """
                SELECT id, artisan_id, name, craft_type, cluster, location,
                       algorand_wallet, ed25519_pubkey, status, approved_at, created_at
                FROM artisans WHERE did = %s
                """,
                (did,),
            )
            artisan = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if not artisan:
            return jsonify({"error": "Artisan not found"}), 404

        artisan = dict(artisan)
        if artisan["status"] != "approved":
            return jsonify({"error": "Artisan not yet approved", "status": artisan["status"]}), 403

        return jsonify({
            "did":             did,
            "name":            artisan["name"],
            "craft_type":      artisan["craft_type"],
            "cluster":         artisan["cluster"],
            "location":        artisan["location"],
            "algorand_wallet": artisan["algorand_wallet"],
            "ed25519_pubkey":  artisan["ed25519_pubkey"],
            "status":          artisan["status"],
            "approved_at":     artisan["approved_at"],
            "created_at":      artisan["created_at"],
        })

    except Exception as exc:
        log.error("resolve_artisan error: %s", exc)
        return jsonify({"error": "Artisan resolution failed"}), 500


# ── DID resolution endpoints ──────────────────────────────────────────────────

@app.route("/did/<path:did>", methods=["GET"])
def resolve_did_endpoint(did: str):
    """
    Resolve a DID to its W3C-compliant DID Document.
    W3C DID Core 1.0 — https://www.w3.org/TR/did-core/
    """
    try:
        if not re.match(r"^did:[a-z]+:[a-zA-Z0-9._\-:]+$", did):
            return jsonify({"error": "Invalid DID format"}), 400

        conn = get_db_connection()
        cur  = dict_cursor(conn)
        try:
            cur.execute(
                """
                SELECT institution, institution_address, address, public_key,
                       domain, registered_at, wallet_version, revoked
                FROM did_registry
                WHERE did = %s
                LIMIT 1
                """,
                (did,),
            )
            row = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if not row:
            return jsonify({"error": "DID not found"}), 404

        if row.get("revoked") == 1:
            return jsonify({"error": "DID has been revoked"}), 410

        institution_address = row.get("institution_address") or row.get("address", "")
        registered_at       = row.get("registered_at", "")
        public_key_b64      = row.get("public_key", "")

        document = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "id": did,
            "controller": did,
            "verificationMethod": [
                {
                    "id":                 f"{did}#key-1",
                    "type":               "Ed25519VerificationKey2020",
                    "controller":         did,
                    "publicKeyMultibase": f"z{public_key_b64}" if public_key_b64 else "",
                }
            ],
            "authentication":  [f"{did}#key-1"],
            "assertionMethod": [f"{did}#key-1"],
            "service": [
                {
                    "id":              f"{did}#skillchain-issuer",
                    "type":            "SkillChainIssuer",
                    "serviceEndpoint": {
                        "institutionName":  row.get("institution", ""),
                        "domain":           row.get("domain", ""),
                        "algorandAddress":  institution_address,
                        "network":          "algorand-testnet",
                        "registeredAt":     registered_at,
                        "walletVersion":    row.get("wallet_version", 1),
                    },
                },
                {
                    "id":              f"{did}#linked-domain",
                    "type":            "LinkedDomains",
                    "serviceEndpoint": f"https://{row.get('domain', '')}",
                },
            ],
        }

        response = jsonify(document)
        response.headers["Content-Type"] = "application/did+ld+json"
        return response, 200

    except Exception as exc:
        log.error("resolve_did_endpoint error: %s", exc)
        return jsonify({"error": "DID resolution error"}), 500


@app.route("/did/view/<path:did>", methods=["GET"])
def view_did_endpoint(did: str):
    try:
        if not re.match(r"^did:[a-z]+:[a-zA-Z0-9._\-:]+$", did):
            return "Invalid DID format", 400

        conn = get_db_connection()
        cur  = dict_cursor(conn)
        try:
            cur.execute(
                """
                SELECT institution, institution_address, address, domain, registered_at
                FROM did_registry WHERE did = %s LIMIT 1
                """,
                (did,),
            )
            row = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        name    = row.get("institution", "") if row else ""
        address = row.get("institution_address") or row.get("address", "") if row else ""

    except Exception as exc:
        log.error("view_did_endpoint error: %s", exc)
        name    = ""
        address = ""
        row     = None

    if not row:
        from flask import render_template_string
        return render_template_string(
            "<h2>DID Not Found</h2><p>No identity document found for: <code>{{ did }}</code></p>",
            did=did
        ), 404

    subject = did

    from flask import render_template_string
    return render_template_string("""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Identity: {{ subject }}</title>
<style>body{font-family:-apple-system,sans-serif;background:#f5f5f5;margin:0;padding:40px 20px}
.card{max-width:580px;margin:0 auto;background:white;border-radius:12px;padding:28px;border:1px solid #e5e5e5}
h2{margin:0 0 4px;font-size:20px}.sub{font-size:13px;color:#666;margin-bottom:20px}
.row{display:flex;justify-content:space-between;align-items:flex-start;padding:10px 0;border-bottom:1px solid #f0f0f0;font-size:13px;gap:16px}
.row:last-child{border-bottom:none}.label{color:#888;min-width:120px}
.value{font-family:monospace;word-break:break-all;color:#1a1a1a}
.vault-badge{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:600;background:#e8eaf6;color:#1a237e;padding:4px 10px;border-radius:99px;margin-top:16px}
.raw-btn{display:inline-block;margin-top:16px;padding:9px 18px;font-size:13px;font-weight:500;background:#1a1a1a;color:white;border-radius:8px;text-decoration:none}</style>
</head><body><div class="card">
<h2>Institution Identity</h2>
<div class="sub">Decentralised Identity Document - W3C DID Core 1.0</div>
{% if address %}<div class="row"><span class="label">On-chain Address</span><span class="value">{{ address }}</span></div>{% endif %}
{% if name %}<div class="row"><span class="label">Institution</span><span class="value">{{ name }}</span></div>{% endif %}
<div class="row"><span class="label">DID</span><span class="value" style="font-size:11px">{{ subject }}</span></div>
<div class="vault-badge">Vault Secured - Private keys never exposed</div><br>
<a class="raw-btn" href="/did/{{ did }}">View Raw DID Document (JSON-LD)</a>
</div></body></html>""", subject=subject, name=name, address=address, did=did)


# ── Institution dashboard ─────────────────────────────────────────────────────

@app.route("/institution/<path:did>", methods=["GET"])
def institution_dashboard(did: str):
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        try:
            cur.execute(
                "SELECT institution, institution_address, domain FROM did_registry WHERE address = %s OR did = %s LIMIT 1",
                (did, did)
            )
            row = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if not row:
            inst_name    = "Unknown Institution"
            inst_address = did
            domain       = ""
        else:
            inst_name    = row[0] if isinstance(row, (list, tuple)) else row["institution"]
            inst_address = row[1] if isinstance(row, (list, tuple)) else row["institution_address"]
            domain       = row[2] if isinstance(row, (list, tuple)) else row["domain"]

        addr_display = (inst_address[:8] + "..." + inst_address[-6:]) if inst_address and len(inst_address) > 16 else (inst_address or "")

        from flask import render_template_string
        return render_template_string("""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>{{ name }} - SkillChain</title>
<style>body{font-family:-apple-system,sans-serif;background:#f5f5f5;margin:0;padding:40px 20px}
.wrap{max-width:700px;margin:0 auto}.profile-card{background:white;border-radius:12px;padding:24px;border:1px solid #e5e5e5;margin-bottom:16px}
h2{margin:0 0 4px;font-size:22px}.domain{font-size:13px;color:#666;margin-bottom:20px}
.row{display:flex;gap:16px;align-items:flex-start;padding:9px 0;border-bottom:1px solid #f0f0f0;font-size:13px}
.row:last-child{border-bottom:none}.lbl{color:#888;min-width:160px}.val{font-family:monospace;word-break:break-all}
.vault-badge{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;background:#e8eaf6;color:#1a237e;padding:5px 12px;border-radius:99px;margin-top:14px}
.section-title{font-size:14px;font-weight:600;margin-bottom:14px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px 12px;background:#f9f9f9;border-bottom:2px solid #e5e5e5;color:#555;font-size:12px}
td{padding:10px 12px;border-bottom:1px solid #f0f0f0;color:#888;font-style:italic}
.placeholder{text-align:center;padding:32px 16px;color:#bbb;font-size:13px}
.back{display:inline-block;margin-bottom:16px;font-size:13px;color:#2563eb;text-decoration:none}</style>
</head><body><div class="wrap">
<a class="back" href="/">Back to SkillChain</a>
<div class="profile-card">
<h2>{{ name }}</h2><div class="domain">{{ domain }}</div>
<div class="row"><span class="lbl">DID</span><span class="val" style="font-size:11px">{{ did }}</span></div>
<div class="row"><span class="lbl">On-chain Identity Address</span><span class="val">{{ addr_display }}</span></div>
<div class="vault-badge">Vault Secured</div>
</div>
<div class="profile-card">
<div class="section-title">Certificates Issued</div>
<table><thead><tr><th>Certificate ID</th><th>Issued To</th><th>Status</th></tr></thead>
<tbody><tr><td colspan="3"><div class="placeholder">Certificate listing coming soon.</div></td></tr></tbody>
</table></div></div></body></html>""",
            name=inst_name, did=did, addr_display=addr_display, domain=domain)

    except Exception as exc:
        log.error("institution_dashboard error: %s", exc)
        return jsonify({"error": "Dashboard unavailable"}), 500


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """
    Structured health check.

    Returns::

        {
          "status": "ok" | "degraded",
          "vault": {
            "enabled":   true | false,
            "reachable": true | false | null,
            "mode":      "vault" | "aes_gcm"
          },
          "database": "ok" | "error",
          "timestamp": "<iso8601>"
        }

    Never raises — all exceptions are caught and reflected in the response.
    """
    import datetime

    # ── Vault status ─────────────────────────────────────────────────────────
    vault_enabled  = False
    vault_reachable: bool | None = None
    vault_mode     = "aes_gcm"

    try:
        from vault_client import is_vault_enabled, health_check as vault_health_check
        vault_enabled = is_vault_enabled()
        if vault_enabled:
            vault_reachable = vault_health_check()   # True / False, never raises
            vault_mode      = "vault"
        # else: vault_reachable stays None, mode stays "aes_gcm"
    except Exception as exc:
        log.warning("Health: vault_client import/check failed — %s", exc)
        # vault_enabled / vault_reachable / vault_mode retain their defaults

    # ── Database status ───────────────────────────────────────────────────────
    db_status = "ok"
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        try:
            cur.execute("SELECT 1")
        finally:
            cur.close()
            conn.close()
    except Exception as exc:
        log.warning("Health: database check failed — %s", exc)
        db_status = "error"

    # ── Overall status ────────────────────────────────────────────────────────
    # Degraded if DB is down, or if Vault is enabled but unreachable.
    degraded = (
        db_status == "error"
        or (vault_enabled and vault_reachable is False)
    )
    overall = "degraded" if degraded else "ok"

    return jsonify({
        "status": overall,
        "vault": {
            "enabled":   vault_enabled,
            "reachable": vault_reachable,
            "mode":      vault_mode,
        },
        "database":  db_status,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    })


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
