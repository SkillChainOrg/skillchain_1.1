"""
app.py — SkillChain Flask API.

Startup sequence
----------------
1. Create Flask app + rate limiter.
2. Run DB migrations (idempotent — safe on every deploy).
3. Initialise certificate and DID tables.
4. Register all routes.
"""

import hashlib
import io
import logging
import os
import secrets
import sqlite3
import time
import zipfile

from flask import Flask, request, jsonify, render_template
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
    create_digilocker_request,
    get_request_status,
    fetch_document_data,
    hash_document_data,
    revoke_access,
)
from queue_service import queue_batch, get_batch_status
import db_migrations

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
DB_PATH   = os.getenv("DB_PATH", "skillchain.db")

# ── Startup: migrations then table initialisation ─────────────────────────────
db_migrations.run_migrations()
init_db()
init_did_db()


# ── Image normalisation helper ────────────────────────────────────────────────

def normalize_and_hash(file_bytes: bytes) -> str:
    img = Image.open(io.BytesIO(file_bytes))
    exif = img.getexif()
    exif.clear()
    img    = img.convert("RGB")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return hashlib.sha256(buffer.getvalue()).hexdigest()


# ── Batch issuance ────────────────────────────────────────────────────────────

@app.route("/issue/batch", methods=["POST"])
def issue_batch():

    api_key = request.headers.get("X-API-Key")
    institution = validate_api_key(api_key)
    if not institution:
        return jsonify({"error": "Invalid or missing API key"}), 401

    zip_file = request.files.get("certificates")
    if not zip_file:
        return jsonify({"error": "No zip file uploaded"}), 400

    doc_type = request.form.get("doc_type", "academic")

    # Determine per-institution signing context
    inst_id = (
        institution.get("institution_id")
        if institution.get("wallet_version", 1) == 2
        else None
    )

    batch_id = secrets.token_hex(8)
    jobs = []

    with zipfile.ZipFile(zip_file) as zf:
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
                signature = sign_credential(cert_hash)
                del file_bytes

                jobs.append({
                    "cert_hash": cert_hash,
                    "signature": signature,
                    "filename":  filename,
                    "doc_type":  doc_type,
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
        "message":    "Consent received. Call /digilocker/verify to fetch and verify document.",
    })


@app.route("/digilocker/verify", methods=["POST"])
@limiter.limit("20 per minute")
def digilocker_verify():
    data       = request.get_json()
    request_id = data.get("request_id")
    doc_type   = data.get("doc_type", "DGDEG")
    org_id     = data.get("org_id", "in.gov.cbse")

    if not request_id:
        return jsonify({"error": "request_id required"}), 400

    from digilocker_service import verify_with_identity
    return jsonify(verify_with_identity(request_id, doc_type, org_id))


# ── Core routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/issue", methods=["POST"])
@limiter.limit("10 per minute")
def issue():
    api_key = request.headers.get("X-API-Key")
    institution = validate_api_key(api_key)
    if not institution:
        return jsonify({"error": "Invalid or missing API key"}), 401

    if "certificate" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["certificate"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    doc_type = request.form.get("doc_type", "academic")
    file_bytes = file.read()
    cert_hash = normalize_and_hash(file_bytes)
    del file_bytes

    inst_id = (
        institution.get("institution_id")
        if institution.get("wallet_version", 1) == 2
        else None
    )

    signature = sign_credential(cert_hash)
    result    = anchor_hash(cert_hash, doc_type, institution, signature,
                            institution_id=inst_id)

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
    return jsonify(verify_email_token(token))


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
    return jsonify(approve_registration(registration_id))


@app.route("/admin/revoke-issuer/<institution_id>", methods=["POST"])
def admin_revoke_issuer(institution_id):
    """
    Soft-revoke an institution's issuing privileges.

    Body (JSON):
        {"reason": "string"}  — optional human-readable reason

    Effect:
        Sets did_registry.revoked=1, revoked_at=<now>, revoked_reason=<reason>
        for the matching institution_id.

    Note:
        This is a soft revocation — the Vault key is NOT deleted.
        Use vault_client.delete_key(institution_id) for hard off-boarding.
        Future /verify calls for certs issued by this institution return
        {"valid": false, "reason": "issuer_revoked"}.
    """
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    data   = request.get_json(silent=True) or {}
    reason = data.get("reason", "")

    conn = sqlite3.connect(DB_PATH)
    cur  = conn.execute(
        """
        UPDATE did_registry
        SET revoked        = 1,
            revoked_at     = ?,
            revoked_reason = ?
        WHERE institution_id = ?
        """,
        (time.strftime("%Y-%m-%dT%H:%M:%SZ"), reason, institution_id),
    )
    conn.commit()
    rows_affected = cur.rowcount
    conn.close()

    if rows_affected == 0:
        return jsonify({"error": f"No institution found with id '{institution_id}'"}), 404

    log.warning(
        "Institution revoked: institution_id=%s reason=%r", institution_id, reason
    )
    return jsonify({
        "success":        True,
        "institution_id": institution_id,
        "revoked_at":     time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reason":         reason,
        "note":           "Soft revocation — Vault key retained. "
                          "Call vault_client.delete_key() for hard off-boarding.",
    })


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """
    Returns service health including Vault connectivity status.

    A Vault error degrades status to 'degraded' but never crashes this endpoint.
    Response examples:
        {"status": "ok",       "vault": "connected"}
        {"status": "degraded", "vault": "sealed"}
        {"status": "ok",       "vault": "disabled"}
    """
    vault_status = "disabled"

    try:
        from vault_client import is_vault_enabled, _get_client
        if is_vault_enabled():
            client       = _get_client()   # raises RuntimeError if sealed/unreachable
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