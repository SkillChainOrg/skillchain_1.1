"""
digilocker_service.py — Setu DigiLocker integration for SkillChain.

FIXES:
  - verify_with_identity was fundamentally broken:
      • At issuance we hash the *image* (normalize_and_hash → SHA-256 of PNG).
      • The old code hashed name+roll from the XML document and tried to look
        that up on the blockchain — these two hashes can NEVER match.
  - Rewritten flow:
      1. DigiLocker fetches the degree document → extract cert_number (roll).
      2. Look up the stored cert_hash by cert_number in local DB.
      3. The employer has also submitted the certificate image → hash it.
      4. Compare submitted image hash vs stored cert_hash.
      5. HMAC + IPFS + Algorand full verification.
      6. Identity: SHA-256(DigiLocker name) vs stored issued_to hash.
  - get_anchored_name_hash() removed — it parsed a deprecated note format
    and looked for 'name_hash' that was never written.  Identity check now
    uses the issued_to column written at issuance time.
"""

import hashlib
import os
import requests
import xml.etree.ElementTree as ET

from dotenv import load_dotenv

load_dotenv()

BASE_URL            = os.getenv("SETU_BASE_URL",            "https://dg-sandbox.setu.co")
CLIENT_ID           = os.getenv("SETU_CLIENT_ID")
CLIENT_SECRET       = os.getenv("SETU_CLIENT_SECRET")
PRODUCT_INSTANCE_ID = os.getenv("SETU_PRODUCT_INSTANCE_ID")


def setu_headers() -> dict:
    return {
        "Content-Type":          "application/json",
        "x-client-id":           CLIENT_ID,
        "x-client-secret":       CLIENT_SECRET,
        "x-product-instance-id": PRODUCT_INSTANCE_ID,
    }


# ── DigiLocker session management ─────────────────────────────────────────────

def create_digilocker_request(redirect_url: str) -> dict:
    response = requests.post(
        f"{BASE_URL}/api/digilocker",
        headers=setu_headers(),
        json={"redirectUrl": redirect_url},
        timeout=10
    )
    response.raise_for_status()
    data = response.json()
    return {
        "request_id":    data["id"],
        "digilocker_url": data["url"],
        "expires_at":    data["validUpto"],
    }


def get_request_status(request_id: str) -> dict:
    response = requests.get(
        f"{BASE_URL}/api/digilocker/{request_id}",
        headers=setu_headers(),
    )
    data = response.json()
    return {
        "status":     data.get("status"),
        "user":       data.get("digilockerUserDetails", {}),
        "request_id": request_id,
    }


def get_verified_name(request_id: str) -> str:
    """Return the DigiLocker-verified Aadhaar name for a completed session."""
    response = requests.get(
        f"{BASE_URL}/api/digilocker/{request_id}",
        headers=setu_headers(),
    )
    data = response.json()
    user = data.get("digilockerUserDetails", {})
    return user.get("name", "")


def revoke_access(request_id: str) -> bool:
    response = requests.post(
        f"{BASE_URL}/api/digilocker/{request_id}/revoke",
        headers=setu_headers(),
    )
    return response.status_code == 200


# ── Document fetching ─────────────────────────────────────────────────────────

def fetch_document_data(request_id: str, doc_type: str, org_id: str) -> dict:
    """
    Fetch a structured document from DigiLocker via Setu.

    Returns a dict with at minimum:
        name:        Candidate name from the document
        cert_number: Roll number / certificate number (the primary lookup key)
        raw_xml:     Raw XML string for debugging
    """
    response = requests.post(
        f"{BASE_URL}/api/digilocker/{request_id}/fetch",
        headers={**setu_headers(), "Accept": "application/xml"},
        json={"docType": doc_type, "orgId": org_id},
    )

    xml_content = response.text
    root = ET.fromstring(xml_content)

    def safe_text(element):
        return element.text.strip() if element is not None and element.text else ""

    # cert_number maps to RollNo for academic documents.
    # For non-academic docs the field may be at a different path — extend here.
    cert_number = (
        safe_text(root.find(".//Candidate/RollNo"))
        or safe_text(root.find(".//CertificateNumber"))
        or safe_text(root.find(".//DocNumber"))
    )

    return {
        "name":        safe_text(root.find(".//Candidate/Name")),
        "cert_number": cert_number,
        "raw_xml":     xml_content,
    }


# ── Canonicalisation helpers (kept for reference — no longer used in main flow) ──

def canonicalize_document(doc: dict) -> str:
    name = doc.get("name", "").strip().lower()
    roll = doc.get("cert_number", "").strip().lower()
    return f"name:{name}|roll:{roll}"


def hash_document_data(doc: dict) -> str:
    """SHA-256 of the canonical document string (legacy helper)."""
    canonical = canonicalize_document(doc)
    return hashlib.sha256(canonical.encode()).hexdigest()


# ── Main verification flow ─────────────────────────────────────────────────────

def verify_with_identity(
    request_id: str,
    doc_type: str,
    org_id: str,
    submitted_cert_hash: str | None = None,
) -> dict:
    """
    Full DigiLocker-backed certificate verification.

    FIXED flow (replaces the broken name+roll hash approach):

      1. Fetch document from DigiLocker → extract cert_number and name.
      2. Look up cert_number in local DB → retrieve stored cert_hash.
      3. If the employer also submitted the certificate image (submitted_cert_hash),
         compare it with the stored cert_hash.
      4. Run full HMAC + IPFS + Algorand verification via verify_by_cert_number().
      5. Revoke DigiLocker session.
      6. Return combined result.

    Args:
        request_id:          Setu DigiLocker session ID (post-consent).
        doc_type:            DigiLocker document type code (e.g. "DGDEG").
        org_id:              Issuing organisation ID (e.g. "in.gov.cbse").
        submitted_cert_hash: SHA-256 of the certificate image submitted by the
                             employer (from normalize_and_hash).  If None, only
                             cert_number lookup + HMAC/IPFS/chain checks run;
                             the image-match step is skipped.

    Returns:
        Verification result dict with valid, identity_verified, and detail fields.
    """
    from algorand_service import verify_by_cert_number

    # Step 1 — Fetch document
    try:
        doc = fetch_document_data(request_id, doc_type, org_id)
    except Exception as exc:
        revoke_access(request_id)
        return {"valid": False, "reason": f"DigiLocker fetch failed: {exc}"}

    cert_number     = doc.get("cert_number", "").strip()
    digilocker_name = doc.get("name", "").strip()

    if not cert_number:
        revoke_access(request_id)
        return {
            "valid":  False,
            "reason": "Could not extract cert/roll number from DigiLocker document",
            "detail": "Check doc_type and org_id — the field path may differ for this document type",
        }

    # Step 2–5 — Look up cert, verify hash + HMAC + chain
    result = verify_by_cert_number(
        cert_number=cert_number,
        submitted_cert_hash=submitted_cert_hash or "",  # empty → skips image match
        digilocker_name=digilocker_name or None,
    )

    # Step 6 — Always revoke session after use
    revoke_access(request_id)

    return {
        **result,
        "cert_number_from_digilocker": cert_number,
        "source":                      "DigiLocker",
        "government_verified":         True,
    }