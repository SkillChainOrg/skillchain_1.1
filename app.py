from flask import Flask, request, jsonify, render_template
from PIL import Image
from did_service import init_did_db, validate_api_key, register_did, sign_credential
from algorand_service import init_db, anchor_hash, verify_hash
import hashlib, io
import os
from did_service import (init_did_db, validate_api_key, register_did,
                         sign_credential, request_registration,
                         verify_email_token, get_pending_registrations,
                         approve_registration)


ADMIN_KEY = os.getenv("ADMIN_KEY", "skillchain-admin-secret")


app = Flask(__name__)
init_db()
init_did_db()

def normalize_and_hash(file_bytes: bytes) -> str:
    img = Image.open(io.BytesIO(file_bytes))
    exif = img.getexif()
    exif.clear()
    img = img.convert("RGB")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    normalized = buffer.getvalue()
    return hashlib.sha256(normalized).hexdigest()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data or "institution_name" not in data:
        return jsonify({"error": "institution_name required"}), 400
    result = register_did(data["institution_name"])
    return jsonify(result)

@app.route("/issue", methods=["POST"])
def issue():
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return jsonify({"error": "Missing API key"}), 401

    institution = validate_api_key(api_key)
    if not institution:
        return jsonify({"error": "Invalid API key — register your institution first"}), 403

    if "certificate" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["certificate"]
    doc_type = request.form.get("doc_type", "academic")

    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    file_bytes = file.read()
    cert_hash = normalize_and_hash(file_bytes)
    signature = sign_credential(cert_hash)
    tx_id = anchor_hash(cert_hash, doc_type)

    return jsonify({
        "success": True,
        "cert_hash": cert_hash,
        "tx_id": tx_id,
        "issued_by": institution["institution"],
        "did": institution["did"],
        "explorer_url": f"https://testnet.explorer.perawallet.app/tx/{tx_id}"
    })

@app.route("/verify", methods=["POST"])
def verify():
    if "certificate" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["certificate"]

    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    file_bytes = file.read()
    cert_hash = normalize_and_hash(file_bytes)
    result = verify_hash(cert_hash)
    return jsonify(result)

@app.route("/request-registration", methods=["POST"])
def request_reg():
    data = request.get_json()
    required = ["institution_name", "email", "domain"]
    if not all(k in data for k in required):
        return jsonify({"error": "institution_name, email, domain required"}), 400
    result = request_registration(data["institution_name"], data["email"], data["domain"])
    return jsonify(result)

@app.route("/verify-email", methods=["GET"])
def verify_email():
    token = request.args.get("token")
    if not token:
        return jsonify({"error": "Token required"}), 400
    result = verify_email_token(token)
    return jsonify(result)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})
@app.route("/admin/pending", methods=["GET"])
def admin_pending():
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify(get_pending_registrations())

@app.route("/admin/approve/<registration_id>", methods=["POST"])
def admin_approve(registration_id):
    if request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return jsonify({"error": "Unauthorized"}), 403
    result = approve_registration(registration_id)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
    