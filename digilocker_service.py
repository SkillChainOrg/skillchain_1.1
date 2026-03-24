import os, requests, hashlib, io
from PIL import Image
from dotenv import load_dotenv
import fitz
import xml.etree.ElementTree as ET

load_dotenv()

BASE_URL            = os.getenv("SETU_BASE_URL", "https://dg-sandbox.setu.co")
CLIENT_ID           = os.getenv("SETU_CLIENT_ID")
CLIENT_SECRET       = os.getenv("SETU_CLIENT_SECRET")
PRODUCT_INSTANCE_ID = os.getenv("SETU_PRODUCT_INSTANCE_ID")

def setu_headers() -> dict:
    return {
        "Content-Type":        "application/json",
        "x-client-id":         CLIENT_ID,
        "x-client-secret":     CLIENT_SECRET,
        "x-product-instance-id": PRODUCT_INSTANCE_ID
    }

def create_digilocker_request(redirect_url: str) -> dict:
    """
    Step 1 — create a request, get back a URL to send the user to.
    """
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
    """
    Step 2 — poll this after user returns from DigiLocker.
    Status changes from 'unauthenticated' to 'authenticated' on consent.
    """
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

"""def fetch_document(request_id: str, doc_type: str, org_id: str) -> dict:
    
    Step 3 — fetch the actual document after user has consented.
    Returns a file URL to download.
    
    Common doc_type + org_id pairs:
    Degree certificate:     docType=DGDEG, orgId varies by university
    CBSE marksheet:         docType=CBSMK, orgId=in.gov.cbse  
    PAN card:               docType=PANCR, orgId=in.gov.income-tax
    Driving licence:        docType=DRVLC, orgId varies by state RTO
    
    response = requests.post(
        f"{BASE_URL}/api/digilocker/{request_id}/fetch",
        headers=setu_headers(),
        json={"docType": doc_type, "orgId": org_id}
    )
    data = response.json()
    return {
        "file_url": data.get("fileUrl"),
        "doc_type": doc_type,
        "org_id": org_id
    }"""


def fetch_document_xml(request_id: str, doc_type: str, org_id: str) -> dict:
    """
    Fetches the structured XML version of the document.
    Returns parsed fields — no PDF download needed.
    """
    response = requests.post(
        f"{BASE_URL}/api/digilocker/{request_id}/fetch",
        headers={**setu_headers(), "Accept": "application/xml"},
        json={"docType": doc_type, "orgId": org_id}
    )
    
    xml_content = response.text
    root = ET.fromstring(xml_content)
    
    # Parse name from XML structure
    name_element = root.find(".//Candidate/Name")
    roll_element = root.find(".//Candidate/RollNo")
    
    return {
        "name": name_element.text.strip() if name_element is not None else "",
        "roll_number": roll_element.text.strip() if roll_element is not None else "",
        "raw_xml": xml_content  # keep for hashing if needed
    }

def download_and_hash(file_url: str) -> str:
    """
    Downloads document from DigiLocker, normalises to PNG, hashes, discards.
    Never stored. Handles both PDF and image formats.
    DPDP compliance: document lives in memory only, deleted after hashing.
    """
    response = requests.get(file_url, headers=setu_headers(), timeout=15)
    response.raise_for_status()
    file_bytes = response.content
    content_type = response.headers.get("Content-Type", "")

    try:
        if "pdf" in content_type or file_bytes[:4] == b"%PDF":
            # PDF path — render page 1 to image, then normalise
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            page = doc.load_page(0)
            # Render at 150 DPI — consistent resolution = consistent hash
            mat = fitz.Matrix(150/72, 150/72)
            pix = page.get_pixmap(matrix=mat, colorspace=fitz.csRGB)
            img_bytes = pix.tobytes("png")
            doc.close()
            del pix
        else:
            # Image path — existing PIL normalisation
            img = Image.open(io.BytesIO(file_bytes))
            img.getexif().clear()
            img = img.convert("RGB")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            img_bytes = buf.getvalue()
            del buf

        cert_hash = hashlib.sha256(img_bytes).hexdigest()
    finally:
        # Always discard — even on exception
        del file_bytes, img_bytes

    return cert_hash

def revoke_access(request_id: str) -> bool:
    """
    Step 5 — revoke token after you're done. 
    Good practice — don't hold access longer than needed.
    """
    response = requests.post(
        f"{BASE_URL}/api/digilocker/{request_id}/revoke",
        headers=setu_headers()
    )
    return response.status_code == 200

def mock_digilocker_verify(cert_hash: str) -> dict:
    """
    Mock DigiLocker verification for sandbox testing.
    In production this is replaced by the real consent flow.
    """
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

def verify_with_identity(request_id: str, doc_type: str, org_id: str):
    from algorand_service import verify_hash, get_anchored_name_hash
    import hashlib
    
    doc = fetch_document_xml(request_id, doc_type, org_id)
    if not doc.get("file_url"):
        return {"error": "Could not fetch document from DigiLocker"}

    cert_hash = download_and_hash(doc["file_url"])
    result = verify_hash(cert_hash)
    
    if not result.get("valid"):
        revoke_access(request_id)
        return {**result, "identity_verified": False}

    verified_name = get_verified_name(request_id)
    name_hash = hashlib.sha256(
        verified_name.strip().lower().encode()
    ).hexdigest()
    
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
            else "Identity could not be verified"
        )
    }
    
def download_and_hash(file_url: str) -> str:
    response = requests.get(file_url, headers=setu_headers())
    file_bytes = response.content
    
    img = Image.open(io.BytesIO(file_bytes))
    exif = img.getexif()
    exif.clear()
    img = img.convert("RGB")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    normalized = buffer.getvalue()
    
    cert_hash = hashlib.sha256(normalized).hexdigest()
    
    # explicitly delete from memory — never stored
    del file_bytes, normalized, buffer
    
    return cert_hash