import os, requests, hashlib, io
from PIL import Image
from dotenv import load_dotenv

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

def fetch_document(request_id: str, doc_type: str, org_id: str) -> dict:
    """
    Step 3 — fetch the actual document after user has consented.
    Returns a file URL to download.
    
    Common doc_type + org_id pairs:
    Degree certificate:     docType=DGDEG, orgId varies by university
    CBSE marksheet:         docType=CBSMK, orgId=in.gov.cbse  
    PAN card:               docType=PANCR, orgId=in.gov.income-tax
    Driving licence:        docType=DRVLC, orgId varies by state RTO
    """
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
    }

def download_and_hash(file_url: str) -> str:
    """
    Step 4 — download the file from DigiLocker, normalize, hash.
    This hash is what we check against Algorand.
    """
    response = requests.get(file_url, headers=setu_headers())
    file_bytes = response.content
    
    img = Image.open(io.BytesIO(file_bytes))
    exif = img.getexif()
    exif.clear()
    img = img.convert("RGB")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    normalized = buffer.getvalue()
    
    return hashlib.sha256(normalized).hexdigest()

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