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
"""

import hashlib
import io
import logging
import os
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

from algorand_service import init_db, anchor_hash, verify_hash
from did_service import (
    init_did_db,
    validate_api_key,
    register_did,
    sign_credential,
    request_registration,
    verify_email_token,
    get_pending_registrations,
    approve_registration,
    get_algod_client,
)
from digilocker_service import (
    create_digilocker_request,
    get_request_status,
    verify_with_identity,
)
from identity_service import bind_identity, lookup_identity
from queue_service import queue_batch, get_batch_status
import db_migrations
from db import get_db_connection, dict_cursor

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ── App + rate limiter ────────────────────────────────────────────────────────
app = Flask(__name__)
if CORS:
    CORS(app, resources={r"/*": {"origins": "*"}})

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day"],
)

ADMIN_KEY = os.getenv("ADMIN_KEY")
if not ADMIN_KEY:
    raise RuntimeError(
        "ADMIN_KEY environment variable is not set.\n"
        "Generate one: python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "Then set it in Railway -> Variables (or your .env file)."
    )

# ── Startup ───────────────────────────────────────────────────────────────────
db_migrations.run_migrations()
init_db()
init_did_db()


# ── Image normalisation helper ────────────────────────────────────────────────

def normalize_and_hash(file_bytes: bytes) -> str:
    img  = Image.open(io.BytesIO(file_bytes))
    exif = img.getexif()
    exif.clear()
    img    = img.convert("RGB")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return hashlib.sha256(buffer.getvalue()).hexdigest()


# ── Wallet readiness check (Fix 3) ───────────────────────────────────────────

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

        # ── NEW: detect upload mode ───────────────────────────────────────────
        # Priority: explicit multi-file upload > ZIP fallback
        direct_files = request.files.getlist("files")   # NEW – multi-file list
        zip_file     = request.files.get("certificates") # existing ZIP field

        if direct_files:
            # ── NEW BRANCH: multiple files uploaded directly ──────────────────
            if len(direct_files) > 500:                 # NEW – cap at 500
                return jsonify({"error": "Max 500 per batch"}), 400

            ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".pdf"}  # NEW

            for upload in direct_files:                 # NEW
                filename = upload.filename or ""
                ext      = os.path.splitext(filename)[1].lower()

                if ext not in ALLOWED_EXTENSIONS:       # NEW – skip bad types
                    jobs.append({
                        "filename": filename,
                        "error":    f"Unsupported file type: {ext}",
                        "status":   "skipped",
                    })
                    continue

                try:
                    file_bytes  = upload.read()                         # NEW
                    cert_hash   = normalize_and_hash(file_bytes)        # reused
                    del file_bytes

                    signature   = sign_credential(cert_hash, institution_id=inst_id)  # reused

                    basename    = os.path.splitext(os.path.basename(filename))[0]
                    cert_number = basename                              # NEW – no metadata.json in direct mode

                    jobs.append({                                       # same shape as ZIP branch
                        "cert_hash":   cert_hash,
                        "signature":   signature,
                        "filename":    filename,
                        "doc_type":    doc_type,
                        "cert_number": cert_number,
                        "issued_to":   None,  # not available without per-file metadata
                    })

                except Exception as e:                                  # NEW – skip, don't crash
                    log.warning("Skipping %s in direct batch: %s", filename, e)
                    jobs.append({
                        "filename": filename,
                        "error":    str(e),
                        "status":   "hash_failed",
                    })

        elif zip_file:
            # ── EXISTING BRANCH: ZIP upload (unchanged) ───────────────────────
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
                        })
                    except Exception as e:
                        jobs.append({
                            "filename": filename,
                            "error":    str(e),
                            "status":   "hash_failed",
                        })

        else:
            # ── NEW: no files provided at all ─────────────────────────────────
            return jsonify({
                "error": "No files uploaded. Use 'files' (multi-file) or 'certificates' (ZIP)."
            }), 400

        if not jobs:                                                    # NEW – nothing to queue
            return jsonify({"error": "No valid files found in the upload"}), 400

        queue_batch(batch_id, jobs, institution)  # unchanged

        return jsonify({
            "batch_id":       batch_id,
            "queued":         len([j for j in jobs if "cert_hash" in j]),
            "failed_at_hash": len([j for j in jobs if "error" in j]),
            "status_url":     f"/batch/status/{batch_id}",
            "message":        "Certificates hashed and queued for Algorand anchoring",
            # NEW field – tells caller which mode was used
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

# ── PATCH: replace your existing digilocker_start() in app.py with this ──────
#
# The only change vs. the original is that we now read "name" from the
# request body and forward it to create_digilocker_request().
# Every other route in app.py is unchanged.

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

        # Pass user_name into the service so it is stored against this request_id.
        # When the real Setu integration is active, user_name is ignored here
        # because the name comes from DigiLocker itself — but the parameter
        # signature stays the same so no other code changes.
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
    return render_template("index.html")


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

        # Fix 3: wallet readiness check before issuance
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
        )

        return jsonify({
            "success":        True,
            "cert_hash":      cert_hash,
            "tx_id":          result["tx_id"],
            "ipfs_cid":       result.get("ipfs_cid"),
            "wallet_version": result.get("wallet_version", 1),
            "issued_by":      institution["institution"],
            "did":            institution.get("did", ""),
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
        return jsonify(verify_hash(cert_hash))

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

        # Fix 2: honour http_status returned by the service layer
        status_code = result.pop("http_status", 200)
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

        # Fix 2: honour http_status returned by the service layer
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


# ── DID resolution endpoints ──────────────────────────────────────────────────

@app.route("/did/<path:did>", methods=["GET"])
def resolve_did_endpoint(did: str):
    """
    Resolve a DID to its W3C-compliant DID Document.

    The document is constructed directly from did_registry so this endpoint
    works even if w3c_did_service is unavailable. Content-Type is set to
    application/did+ld+json per the W3C DID spec.

    W3C DID Core 1.0 — https://www.w3.org/TR/did-core/
    """
    try:
        import re
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

        # ── W3C DID Document (DID Core 1.0) ──────────────────────────────────
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
        import re
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


# ── Institution dashboard ──────────────────────────────────────────────────────

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
    try:
        vault_status = "disabled"
        try:
            from vault_client import is_vault_enabled, _get_client
            if is_vault_enabled():
                client       = _get_client()
                vault_status = "connected" if client.is_authenticated() else "sealed"
        except Exception as exc:
            vault_status = "sealed"
            log.warning("Health check: Vault unreachable — %s", exc)

        overall = "ok" if vault_status in ("connected", "disabled") else "degraded"
        return jsonify({"status": overall, "vault": vault_status})
    except Exception as exc:
        log.error("health error: %s", exc)
        return jsonify({"status": "error", "detail": str(exc)}), 500


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)