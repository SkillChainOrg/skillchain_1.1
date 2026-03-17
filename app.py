from flask import Flask, request, jsonify, render_template
from PIL import Image
import hashlib, io, os
from algorand_service import init_db, anchor_hash, verify_hash

app = Flask(__name__)
init_db()

def normalize_and_hash(file_bytes: bytes) -> str:
    img = Image.open(io.BytesIO(file_bytes))
    exif = img.getexif()
    exif.clear()
    img = img.convert("RGB")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    normalized = buffer.getvalue()
    return hashlib.sha256(normalized).hexdigest()

@app.route("/issue", methods=["POST"])
def issue():
    if "certificate" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files["certificate"]
    doc_type = request.form.get("doc_type", "academic")
    
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    file_bytes = file.read()
    cert_hash = normalize_and_hash(file_bytes)
    
    tx_id = anchor_hash(cert_hash, doc_type)
    
    return jsonify({
        "success": True,
        "cert_hash": cert_hash,
        "tx_id": tx_id,
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

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)