import os, requests, hashlib
from dotenv import load_dotenv
import xml.etree.ElementTree as ET

load_dotenv()

BASE_URL            = os.getenv("SETU_BASE_URL", "https://dg-sandbox.setu.co")
CLIENT_ID           = os.getenv("SETU_CLIENT_ID")
CLIENT_SECRET       = os.getenv("SETU_CLIENT_SECRET")
PRODUCT_INSTANCE_ID = os.getenv("SETU_PRODUCT_INSTANCE_ID")


def setu_headers() -> dict:
    return {
        "Content-Type": "application/json",
        "x-client-id": CLIENT_ID,
        "x-client-secret": CLIENT_SECRET,
        "x-product-instance-id": PRODUCT_INSTANCE_ID
    }


def create_digilocker_request(redirect_url: str) -> dict:
    response = requests.post(
        f"{BASE_URL}/api/digilocker",
        headers=setu_headers(),
        json={"redirectUrl": redirect_url}
    )
    data = response.json()
    return {
        "request_id": data["id"],
        "digilocker_url": data["url"],
        "expires_at": data["validUpto"]
    }


def get_request_status(request_id: str) -> dict:
    response = requests.get(
        f"{BASE_URL}/api/digilocker/{request_id}",
        headers=setu_headers()
    )
    data = response.json()
    return {
        "status": data.get("status"),
        "user": data.get("digilockerUserDetails", {}),
        "request_id": request_id
    }


# ✅ STEP 1 — Fetch structured data
def fetch_document_data(request_id: str, doc_type: str, org_id: str) -> dict:
    response = requests.post(
        f"{BASE_URL}/api/digilocker/{request_id}/fetch",
        headers={**setu_headers(), "Accept": "application/xml"},
        json={"docType": doc_type, "orgId": org_id}
    )

    xml_content = response.text
    root = ET.fromstring(xml_content)

    def safe_text(element):
        return element.text.strip() if element is not None and element.text else ""

    return {
        "name": safe_text(root.find(".//Candidate/Name")),
        "roll_number": safe_text(root.find(".//Candidate/RollNo")),
        "raw_xml": xml_content
    }


# ✅ STEP 2 — Canonicalization
def canonicalize_document(doc: dict) -> str:
    name = doc.get("name", "").strip().lower()
    roll = doc.get("roll_number", "").strip().lower()

    return f"name:{name}|roll:{roll}"


# ✅ STEP 3 — Hashing
def hash_document_data(doc: dict) -> str:
    canonical = canonicalize_document(doc)
    return hashlib.sha256(canonical.encode()).hexdigest()


def revoke_access(request_id: str) -> bool:
    response = requests.post(
        f"{BASE_URL}/api/digilocker/{request_id}/revoke",
        headers=setu_headers()
    )
    return response.status_code == 200


def mock_digilocker_verify(cert_hash: str) -> dict:
    from algorand_service import verify_hash
    result = verify_hash(cert_hash)
    return {
        **result,
        "source": "DigiLocker (sandbox mock)",
        "government_verified": True,
        "mock": True
    }


def get_verified_name(request_id: str) -> str:
    response = requests.get(
        f"{BASE_URL}/api/digilocker/{request_id}",
        headers=setu_headers()
    )
    data = response.json()
    user = data.get("digilockerUserDetails", {})
    return user.get("name", "")


# ✅ FINAL — Clean verification pipeline
def verify_with_identity(request_id: str, doc_type: str, org_id: str):
    from algorand_service import verify_hash, get_anchored_name_hash

    # Step 1 — Fetch structured document data
    doc = fetch_document_data(request_id, doc_type, org_id)

    # Step 2 — Hash canonical data
    cert_hash = hash_document_data(doc)

    # Step 3 — Verify on blockchain
    result = verify_hash(cert_hash)

    if not result.get("valid"):
        revoke_access(request_id)
        return {**result, "identity_verified": False}

    # Step 4 — Get DigiLocker identity
    verified_name = get_verified_name(request_id)

    name_hash = hashlib.sha256(
        verified_name.strip().lower().encode()
    ).hexdigest()

    # Step 5 — Compare with anchored identity
    anchored_name_hash = get_anchored_name_hash(cert_hash)

    identity_verified = (
        anchored_name_hash != "" and
        name_hash == anchored_name_hash
    )

    revoke_access(request_id)

    return {
        **result,
        "source": "DigiLocker",
        "government_verified": True,
        "identity_verified": identity_verified,
        "identity_check": (
            "Aadhaar name matches certificate holder"
            if identity_verified
            else "Identity mismatch"
        )
    }