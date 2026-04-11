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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from PIL import Image
from identity_service import bind_identity, lookup_identity, hash_name

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

from queue_service import queue_batch, get_batch_status
import db_migrations
from db import get_db_connection

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ── App + rate limiter ────────────────────────────────────────────────────────
app = Flask(__name__)

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
    a dict with cert_number and identity_did:

        {
          "degree_alice.pdf": {
              "cert_number": "CS2024001",
              "identity_did": "did:skillchain:identity:abc123"
          },
          ...
        }

    If metadata.json is absent, cert_number defaults to the filename (without
    extension) and identity is not stored.
    """
    api_key     = request.headers.get("X-API-Key")
    institution = validate_api_key(api_key)
    if not institution:
        return jsonify({"error": "Invalid or missing API key"}), 401

    zip_file = request.files.get("certificates")
    if not zip_file:
        return jsonify({"error": "No zip file uploaded"}), 400

    doc_type = request.form.get("doc_type", "academic")

    inst_id = (
        institution.get("institution_id")
        if institution.get("wallet_version", 1) == 2
        else None
    )

    batch_id = secrets.token_hex(8)
    jobs     = []

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

                identity_did = meta.get("identity_did") or None

                jobs.append({
                    "cert_hash":   cert_hash,
                    "signature":   signature,
                    "filename":    filename,
                    "doc_type":    doc_type,
                    "cert_number": cert_number,
                    "issued_to":   identity_did,
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
    redirect_url = request.json.get(
        "redirect_url", "http://127.0.0.1:5000/digilocker/callback"
    )
    return jsonify(create_digilocker_request(redirect_url))


@app.route("/digilocker/callback", methods=["GET"])
def digilocker_callback():
    request_id = request.args.get("id")
    if not request_id:
        return jsonify({"error": "Missing request id"}), 400

    status = get_request_status(request_id)
    if status["status"] != "authenticated":
        return jsonify({"error": "User has not consented yet"}), 403

    return jsonify({
        "success":    True,
        "request_id": request_id,
        "user":       status["user"],
        "message":    "Consent received. Call /digilocker/bind to create identity anchor, then /digilocker/verify.",
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
    cert_number = request.form.get("cert_number")

    # 🔥 CHANGED: use identity_did instead of name hashing
    identity_did = request.form.get("identity_did") or None

    file_bytes = file.read()
    cert_hash  = normalize_and_hash(file_bytes)
    del file_bytes

    inst_id = (
        institution.get("institution_id")
        if institution.get("wallet_version", 1) == 2
        else None
    )

    signature = sign_credential(cert_hash, institution_id=inst_id)

    result = anchor_hash(
        cert_hash, doc_type, institution, signature,
        institution_id=inst_id,
        cert_number=cert_number,
        issued_to=identity_did,   # 🔥 CHANGED
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

    # 🔥 NEW: accept identity_did for ownership check
    identity_did = request.form.get("identity_did")

    file_bytes = file.read()
    cert_hash  = normalize_and_hash(file_bytes)
    del file_bytes

    result = verify_hash(cert_hash)

    # 🔥 NEW: enforce identity ownership if provided
    if identity_did and result.get("success"):
        issued_to = result.get("issued_to")

        if issued_to and issued_to != identity_did:
            result["success"] = False
            result["reason"]  = "Certificate does not belong to this identity"

    return jsonify(result)


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