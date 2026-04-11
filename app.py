"""
app.py — SkillChain Flask API.

Startup sequence
----------------
1. Create Flask app + rate limiter.
2. Run DB migrations (idempotent — safe on every deploy).
3. Initialise certificate and DID tables.
4. Register all routes.

CHANGES (mock DigiLocker integration):
  - digilocker_service now uses an in-memory mock instead of live Setu API
    calls.  Routes and function signatures are unchanged — swap the two
    private helpers in digilocker_service.py to restore real API calls.
  - /digilocker/verify is now identity-only: accepts only request_id and
    returns identity_did + digilocker_id + name.  submitted_cert_hash,
    doc_type, and org_id are removed until real credentials are available.
  - Removed imports for fetch_document_data, hash_document_data, revoke_access
    (all internal to digilocker_service; routes do not need them directly).
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
)
from digilocker_service import (
    create_digilocker_request,   # starts a DigiLocker session (mock or real)
    get_request_status,          # polls consent status + user details
    verify_with_identity,        # identity-bind entry point (replaces full verify flow)
)
from identity_service import bind_identity, lookup_identity
from queue_service import queue_batch, get_batch_status
import db_migrations
from db import get_db_connection

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

ADMIN_KEY = os.getenv("ADMIN_KEY", "skillchain-admin-secret")

# ── Startup ───────────────────────────────────────────────────────────────────
db_migrations.run_migrations()   # creates/alters all tables first
init_db()                         # algorand_service certificates table
init_did_db()                     # did_service tables (no-ops if already exist)


# ── Image normalisation helper ────────────────────────────────────────────────

def normalize_and_hash(file_bytes: bytes) -> str:
    img  = Image.open(io.BytesIO(file_bytes))
    exif = img.getexif()
    exif.clear()
    img    = img.convert("RGB")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return hashlib.sha256(buffer.getvalue()).hexdigest()


# ── Batch issuance ────────────────────────────────────────────────────────────

@app.route("/issue/batch", methods=["POST"])
def issue_batch():
    """
    Issue certificates in bulk.

    The ZIP may contain an optional 'metadata.json' mapping each filename to
    a dict with cert_number and issued_to_name:

        {
          "degree_alice.pdf": {
              "cert_number": "CS2024001",
              "issued_to_name": "Alice Smith"
          },
          ...
        }

    If metadata.json is absent, cert_number defaults to the filename (without
    extension) and issued_to_name is not stored (identity check skipped).
    """
    api_key     = request.headers.get("X-API-Key")
    institution = validate_api_key(api_key)
    if not institution:
        return jsonify({"error": "Invalid or missing API key"}), 401

    zip_file = request.files.get("certificates")
    if not zip_file:
        return jsonify({"error": "No zip file uploaded"}), 400

    doc_type = request.form.get("doc_type", "academic")

    # FIX: extract institution_id so per-institution keys are used for signing
    inst_id = (
        institution.get("institution_id")
        if institution.get("wallet_version", 1) == 2
        else None
    )

    batch_id = secrets.token_hex(8)
    jobs     = []

    with zipfile.ZipFile(zip_file) as zf:
        # Load optional metadata mapping
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

                # FIX: pass institution_id so per-institution key is used
                signature = sign_credential(cert_hash, institution_id=inst_id)

                # Resolve cert_number and issued_to from metadata.json or fallback
                meta       = cert_meta.get(filename, {})
                basename   = os.path.splitext(os.path.basename(filename))[0]
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

    queue_batch(batch_id, jobs, institution)

    return jsonify({
        "batch_id":       batch_id,
        "queued":         len([j for j in jobs if "cert_hash" in j]),
        "failed_at_hash": len([j for j in jobs if "error" in j]),
        "status_url":     f"/batch/status/{batch_id}",
        "message":        "Certificates hashed and queued for Algorand anchoring",
    })


@app.route("/batch/status/<batch_id>", methods=["GET"])
def batch_status(batch_id):
    api_key = request.headers.get("X-API-Key")
    if not validate_api_key(api_key):
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify(get_batch_status(batch_id))


# ── DigiLocker ────────────────────────────────────────────────────────────────

@app.route("/digilocker/start", methods=["POST"])
def digilocker_start():
    redirect_url = (request.json or {}).get(
        "redirect_url", request.url_root + "digilocker/callback"
    )
    result = create_digilocker_request(redirect_url)
    # Fix #2: replace NXDOMAIN mock URL with internal consent route
    result["digilocker_url"] = f"/kyc-consent?id={result['request_id']}"
    return jsonify(result)


@app.route("/kyc-consent", methods=["GET"])
def kyc_consent():
    """Internal DigiLocker consent simulation page (Fix #2)."""
    req_id = request.args.get("id", "")
    from flask import render_template_string
    return render_template_string("""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>DigiLocker Consent</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:sans-serif;background:#1a237e;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:white;border-radius:16px;width:360px;overflow:hidden}.header{background:#1a237e;padding:20px 24px;color:white}.logo{font-size:12px;opacity:.7;margin-bottom:4px}.title{font-size:18px;font-weight:600}.body{padding:20px 24px}.app{display:flex;align-items:center;gap:12px;background:#f8f9ff;border:1px solid #e8eaf6;border-radius:10px;padding:12px;margin-bottom:16px}.icon{width:40px;height:40px;background:#1a237e;border-radius:8px;display:flex;align-items:center;justify-content:center;color:white;font-size:18px;font-weight:700}.name{font-size:14px;font-weight:600}.desc{font-size:12px;color:#666;margin-top:2px}.item{display:flex;align-items:flex-start;gap:8px;margin-bottom:8px;font-size:13px;color:#555}.item::before{content:"✓";color:#0f6e56;font-weight:700;margin-top:1px;flex-shrink:0}.footer{padding:0 24px 20px;display:flex;gap:10px}.deny{flex:1;padding:10px;font-size:13px;font-weight:500;background:white;border:1px solid #ddd;border-radius:8px;cursor:pointer}.allow{flex:2;padding:10px;font-size:13px;font-weight:500;background:#1a237e;color:white;border:none;border-radius:8px;cursor:pointer}</style>
</head><body><div class="card">
<div class="header"><div class="logo">DigiLocker · Powered by MeitY</div><div class="title">Consent Request</div></div>
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
<button class="allow" onclick="allow()">&#10003; Allow Access</button>
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
    request_id = request.args.get("id")
    if not request_id:
        return jsonify({"error": "Missing request id"}), 400

    status = get_request_status(request_id)

    # ── Demo resilience: self-heal if the session was lost ────────────────────
    # In mock mode the in-memory store is wiped on server restart.  If a valid
    # request_id arrives at /callback but the session no longer exists (status
    # "not_found"), we re-create it so the demo flow never stalls.  In
    # production this branch is unreachable because real Setu sessions are
    # server-side — remove the `if` block and keep only the 403 guard.
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


@app.route("/digilocker/bind", methods=["POST"])
@limiter.limit("20 per minute")
def digilocker_bind():
    """
    Bind a DigiLocker-verified identity to a SkillChain DID.

    Called after the user completes the DigiLocker consent flow.
    Creates a permanent identity anchor (did:skillchain:identity:...) that
    links the government-verified Aadhaar name to a stable DID.

    Body (JSON):
        digilocker_id   : Stable user ID from Setu (required)
        digilocker_name : Government-verified name from the session (required)

    Returns:
        identity_did    : The person's permanent SkillChain identity DID
        created         : True if this is a new anchor, False if it already existed
    """
    data = request.get_json()
    digilocker_id   = data.get("digilocker_id")
    digilocker_name = data.get("digilocker_name")

    if not digilocker_id or not digilocker_name:
        return jsonify({"error": "digilocker_id and digilocker_name are required"}), 400

    try:
        anchor = bind_identity(digilocker_id, digilocker_name)
        return jsonify({
            "success":      True,
            "identity_did": anchor["identity_did"],
            "created":      anchor["created"],
            "message":      (
                "Identity anchor created — this DID is your permanent credential identity"
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
    """
    Look up the identity DID for a DigiLocker user ID.

    Used by institutions and employers to resolve a person's SkillChain DID
    from their DigiLocker ID without re-running the consent flow.
    """
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


@app.route("/digilocker/verify", methods=["POST"])
@limiter.limit("20 per minute")
def digilocker_verify():
    """
    Bind a DigiLocker-verified identity to a SkillChain DID.

    This is the identity stage of verification.  Document fetching,
    certificate hashing, and blockchain anchoring are handled separately
    once real DigiLocker credentials are available.

    Body (JSON):
        request_id : DigiLocker session ID returned by /digilocker/start (required)

    Returns:
        success        — True on success
        identity_did   — did:skillchain:identity:<hash>  (permanent DID)
        digilocker_id  — stable DigiLocker user identifier
        name           — normalised government-verified name
        anchor_new     — True if a new identity anchor was created

    NOTE: doc_type / org_id / submitted_cert_hash are intentionally removed
    from this endpoint.  The certificate-layer check will be a separate
    endpoint once real Setu credentials are in place, keeping concerns clean.
    """
    data       = request.get_json() or {}
    request_id = data.get("request_id")

    if not request_id:
        return jsonify({"error": "request_id is required"}), 400

    result = verify_with_identity(request_id)

    if not result.get("success"):
        return jsonify(result), 422

    return jsonify(result), 200


# ── Core routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/issue", methods=["POST"])
@limiter.limit("10 per minute")
def issue():
    api_key     = request.headers.get("X-API-Key")
    institution = validate_api_key(api_key)
    if not institution:
        return jsonify({"error": "Invalid or missing API key"}), 401

    if "certificate" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["certificate"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    doc_type   = request.form.get("doc_type", "academic")
    cert_number = request.form.get("cert_number")          # optional single-issue
    issued_to_name = request.form.get("issued_to_name")    # optional
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

    # FIX: pass institution_id so per-institution key is used
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
        "hmac_value":     result.get("hmac_value"),
        "wallet_version": result.get("wallet_version", 1),
        "issued_by":      institution["institution"],
        "did":            institution.get("did", ""),
        "explorer_url":   f"https://testnet.explorer.perawallet.app/tx/{result['tx_id']}",
    })


@app.route("/verify", methods=["POST"])
@limiter.limit("30 per minute")
def verify():
    if "certificate" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["certificate"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    file_bytes = file.read()
    cert_hash  = normalize_and_hash(file_bytes)
    return jsonify(verify_hash(cert_hash))


# ── Registration flow ─────────────────────────────────────────────────────────

@app.route("/request-registration", methods=["POST"])
def request_reg():
    data     = request.get_json()
    required = ["institution_name", "email", "domain"]
    if not all(k in data for k in required):
        return jsonify({"error": "institution_name, email, domain required"}), 400
    return jsonify(
        request_registration(data["institution_name"], data["email"], data["domain"])
    )


@app.route("/verify-email", methods=["GET"])
def verify_email():
    token = request.args.get("token")
    if not token:
        return jsonify({"error": "Token required"}), 400
    result = verify_email_token(token)
    status = 200 if result.get("success") else 400
    return jsonify(result), status


# ── Admin routes ──────────────────────────────────────────────────────────────

@app.route("/admin/pending", methods=["GET"])
def admin_pending():
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify(get_pending_registrations())


@app.route("/admin/approve/<registration_id>", methods=["POST"])
def admin_approve(registration_id):
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error": "Unauthorized"}), 403
    try:
        result = approve_registration(registration_id)
        return jsonify(result)

    except Exception as e:
        import traceback
        traceback.print_exc()  # helpful for debugging in logs
        return jsonify({"error": str(e)}), 500


@app.route("/admin/revoke-issuer/<institution_id>", methods=["POST"])
def admin_revoke_issuer(institution_id):
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


# ── DID resolution endpoints ──────────────────────────────────────────────────

@app.route("/did/<path:did>", methods=["GET"])
def resolve_did_endpoint(did: str):
    """
    GET /did/<did>
    Returns a W3C DID Document JSON for the given DID.
    Validates format and returns 404 if not found.

    Added for demo transparency — lets anyone inspect an institution's DID.
    """
    import re
    # Basic DID format validation: must start with "did:"
    if not re.match(r"^did:[a-z]+:[a-zA-Z0-9._\-:]+$", did):
        return jsonify({"error": "Invalid DID format"}), 400

    try:
        from w3c_did_service import resolve_did
        document = resolve_did(did)
    except Exception as exc:
        log.error("DID resolution failed: %s", exc)
        return jsonify({"error": "DID resolution error"}), 500

    if not document:
        return jsonify({"error": "DID not found"}), 404

    return jsonify(document), 200, {"Content-Type": "application/json"}


@app.route("/did/view/<path:did>", methods=["GET"])
def view_did_endpoint(did: str):
    """
    GET /did/view/<did>
    Human-readable identity page for a DID.
    Shows institution name, address, and links to the raw DID document.
    """
    import re
    if not re.match(r"^did:[a-z]+:[a-zA-Z0-9._\-:]+$", did):
        return "Invalid DID format", 400

    try:
        from w3c_did_service import resolve_did
        document = resolve_did(did)
    except Exception as exc:
        log.error("DID view resolution failed: %s", exc)
        document = None

    if not document:
        return render_template_string(
            "<h2>DID Not Found</h2><p>No identity document found for: <code>{{ did }}</code></p>",
            did=did
        ), 404

    # Extract key fields from the DID document
    subject = document.get("id", did)
    service  = document.get("service", [{}])
    name     = ""
    address  = ""
    for svc in service:
        if svc.get("type") == "SkillChainIssuer":
            ep = svc.get("serviceEndpoint", {})
            if isinstance(ep, dict):
                name    = ep.get("institutionName", "")
                address = ep.get("algorandAddress", "")

    from flask import render_template_string
    return render_template_string("""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Identity: {{ subject }}</title>
  <style>
    body { font-family: -apple-system, sans-serif; background: #f5f5f5; margin: 0; padding: 40px 20px; }
    .card { max-width: 580px; margin: 0 auto; background: white; border-radius: 12px;
            padding: 28px; border: 1px solid #e5e5e5; }
    h2 { margin: 0 0 4px; font-size: 20px; }
    .sub { font-size: 13px; color: #666; margin-bottom: 20px; }
    .row { display: flex; justify-content: space-between; align-items: flex-start;
           padding: 10px 0; border-bottom: 1px solid #f0f0f0; font-size: 13px; gap: 16px; }
    .row:last-child { border-bottom: none; }
    .label { color: #888; min-width: 120px; }
    .value { font-family: monospace; word-break: break-all; color: #1a1a1a; }
    .vault-badge { display: inline-flex; align-items: center; gap: 5px; font-size: 11px;
                   font-weight: 600; background: #e8eaf6; color: #1a237e; padding: 4px 10px;
                   border-radius: 99px; margin-top: 16px; }
    .raw-btn { display: inline-block; margin-top: 16px; padding: 9px 18px; font-size: 13px;
               font-weight: 500; background: #1a1a1a; color: white; border-radius: 8px;
               text-decoration: none; }
    .raw-btn:hover { opacity: .85; }
  </style>
</head>
<body>
<div class="card">
  <h2>🏛 {{ name or 'Institution Identity' }}</h2>
  <div class="sub">Decentralised Identity Document — W3C DID Standard</div>
  {% if address %}
  <div class="row">
    <span class="label">On-chain Address</span>
    <span class="value">{{ address }}</span>
  </div>
  {% endif %}
  <div class="row">
    <span class="label">DID</span>
    <span class="value" style="font-size:11px">{{ subject }}</span>
  </div>
  <div class="vault-badge">🔐 Vault Secured — Private keys never exposed</div>
  <br>
  <a class="raw-btn" href="/did/{{ did }}">View Raw DID Document</a>
</div>
</body></html>""",
        subject=subject, name=name, address=address, did=did
    )


# ── Institution dashboard ──────────────────────────────────────────────────────

@app.route("/institution/<path:did>", methods=["GET"])
def institution_dashboard(did: str):
    """
    GET /institution/<did>
    Institution profile page: name, DID, wallet address, vault badge,
    and a placeholder table for certificates issued.
    Structure-only — data fetching will be wired in a future milestone.
    """
    # Look up institution from DB by DID
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
        # Graceful fallback for demo purposes
        inst_name    = "Unknown Institution"
        inst_address = did
        domain       = ""
    else:
        inst_name    = row[0] if isinstance(row, (list, tuple)) else row["institution"]
        inst_address = row[1] if isinstance(row, (list, tuple)) else row["institution_address"]
        domain       = row[2] if isinstance(row, (list, tuple)) else row["domain"]

    # Abbreviate wallet address for display
    addr_display = (inst_address[:8] + "..." + inst_address[-6:]) if inst_address and len(inst_address) > 16 else (inst_address or "—")

    from flask import render_template_string
    return render_template_string("""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{{ name }} — SkillChain</title>
  <style>
    body { font-family: -apple-system, sans-serif; background: #f5f5f5; margin: 0; padding: 40px 20px; }
    .wrap { max-width: 700px; margin: 0 auto; }
    .profile-card { background: white; border-radius: 12px; padding: 24px; border: 1px solid #e5e5e5; margin-bottom: 16px; }
    h2 { margin: 0 0 4px; font-size: 22px; }
    .domain { font-size: 13px; color: #666; margin-bottom: 20px; }
    .row { display: flex; gap: 16px; align-items: flex-start; padding: 9px 0;
           border-bottom: 1px solid #f0f0f0; font-size: 13px; }
    .row:last-child { border-bottom: none; }
    .lbl { color: #888; min-width: 160px; }
    .val { font-family: monospace; word-break: break-all; }
    .vault-badge { display: inline-flex; align-items: center; gap: 6px; font-size: 12px;
                   font-weight: 600; background: #e8eaf6; color: #1a237e; padding: 5px 12px;
                   border-radius: 99px; margin-top: 14px; cursor: default; }
    .vault-badge[title]:hover::after { content: attr(title); position: absolute; background: #333;
      color: white; font-size: 11px; padding: 4px 8px; border-radius: 6px; margin-left: 8px; white-space: nowrap; }
    .section-title { font-size: 14px; font-weight: 600; margin-bottom: 14px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 8px 12px; background: #f9f9f9; border-bottom: 2px solid #e5e5e5; color: #555; font-size: 12px; }
    td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; color: #888; font-style: italic; }
    tr:last-child td { border-bottom: none; }
    .placeholder { text-align: center; padding: 32px 16px; color: #bbb; font-size: 13px; }
    .back { display: inline-block; margin-bottom: 16px; font-size: 13px; color: #2563eb; text-decoration: none; }
  </style>
</head>
<body>
<div class="wrap">
  <a class="back" href="/">← Back to SkillChain</a>
  <div class="profile-card">
    <h2>🏛 {{ name }}</h2>
    <div class="domain">{{ domain }}</div>

    <div class="row"><span class="lbl">DID</span><span class="val" style="font-size:11px">{{ did }}</span></div>
    <div class="row">
      <span class="lbl">On-chain Identity Address</span>
      <span class="val">{{ addr_display }}</span>
    </div>

    <div class="vault-badge" title="Private keys are securely stored and never exposed">
      🔐 Vault Secured
    </div>
  </div>

  <div class="profile-card">
    <div class="section-title">Certificates Issued</div>
    <table>
      <thead>
        <tr>
          <th>Certificate ID</th>
          <th>Issued To</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td colspan="3">
            <div class="placeholder">
              📋 Certificate listing coming soon — data fetching will be enabled in the next milestone.
            </div>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
</body></html>""",
        name=inst_name, did=did, addr_display=addr_display, domain=domain
    )


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
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


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)