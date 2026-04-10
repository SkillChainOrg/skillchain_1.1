"""
digilocker_service.py — Setu DigiLocker integration for SkillChain.
 
CHANGES (identity anchor integration — Option 3):
  - verify_with_identity now:
      1. Fetches DigiLocker user details to extract digilocker_id (the
         stable Setu user identifier, not just the session request_id).
      2. Calls identity_service.bind_identity() to create-or-return the
         person's identity_did.  This is the persistent DID bound to their
         government-verified identity.
      3. Uses verify_identity_against_cert() (identity layer) instead of
         the inline name-hash comparison in algorand_service.
      4. Returns identity_did in the response so callers can reference the
         permanent identity anchor.
  - government_verified is now derived from actual outcomes, not hardcoded True.
  - Added timeout=10 to fetch_document_data to prevent thread exhaustion.
  - submitted_cert_hash is now REQUIRED — returns error if absent.
"""
 
import hashlib
import logging
import os
import requests
import xml.etree.ElementTree as ET
 
from dotenv import load_dotenv
 
load_dotenv()
 
log = logging.getLogger(__name__)
 
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
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    return {
        "request_id":     data["id"],
        "digilocker_url": data["url"],
        "expires_at":     data["validUpto"],
    }
 
 
def get_request_status(request_id: str) -> dict:
    response = requests.get(
        f"{BASE_URL}/api/digilocker/{request_id}",
        headers=setu_headers(),
        timeout=10,
    )
    data = response.json()
    return {
        "status":     data.get("status"),
        "user":       data.get("digilockerUserDetails", {}),
        "request_id": request_id,
    }
 
 
def _get_digilocker_user_details(request_id: str) -> dict:
    """
    Fetch full session details and return the user details block.
 
    Returns dict with at minimum:
        id:   Stable DigiLocker user ID (used as identity anchor key)
        name: Government-verified Aadhaar name
    """
    response = requests.get(
        f"{BASE_URL}/api/digilocker/{request_id}",
        headers=setu_headers(),
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    return data.get("digilockerUserDetails", {})
 
 
def get_verified_name(request_id: str) -> str:
    """Return the DigiLocker-verified Aadhaar name for a completed session."""
    user = _get_digilocker_user_details(request_id)
    return user.get("name", "")
 
 
def revoke_access(request_id: str) -> bool:
    try:
        response = requests.post(
            f"{BASE_URL}/api/digilocker/{request_id}/revoke",
            headers=setu_headers(),
            timeout=10,
        )
        return response.status_code == 200
    except Exception as exc:
        log.warning("Failed to revoke DigiLocker session %s: %s", request_id, exc)
        return False
 
 
# ── Document fetching ─────────────────────────────────────────────────────────
 
def fetch_document_data(request_id: str, doc_type: str, org_id: str) -> dict:
    """
    Fetch a structured document from DigiLocker via Setu.
 
    Returns a dict with at minimum:
        name:        Candidate name from the document
        cert_number: Roll number / certificate number (primary lookup key)
        raw_xml:     Raw XML string for debugging
    """
    response = requests.post(
        f"{BASE_URL}/api/digilocker/{request_id}/fetch",
        headers={**setu_headers(), "Accept": "application/xml"},
        json={"docType": doc_type, "orgId": org_id},
        timeout=10,                             # FIXED: was missing
    )
 
    xml_content = response.text
    MAX_XML_BYTES = 512 * 1024                  # 512 KB guard
    if len(xml_content.encode()) > MAX_XML_BYTES:
        raise ValueError(f"DigiLocker XML response too large ({len(xml_content)} chars)")
 
    root = ET.fromstring(xml_content)
 
    def safe_text(element):
        return element.text.strip() if element is not None and element.text else ""
 
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
 
 
# ── Canonicalisation helpers (legacy — not used in main flow) ─────────────────
 
def canonicalize_document(doc: dict) -> str:
    name = doc.get("name", "").strip().lower()
    roll = doc.get("cert_number", "").strip().lower()
    return f"name:{name}|roll:{roll}"
 
 
def hash_document_data(doc: dict) -> str:
    """SHA-256 of the canonical document string (legacy helper)."""
    canonical = canonicalize_document(doc)
    return hashlib.sha256(canonical.encode()).hexdigest()
 
 
# ── Main verification flow (Option 3 — DID-bound identity) ────────────────────
 
def verify_with_identity(
    request_id: str,
    doc_type: str,
    org_id: str,
    submitted_cert_hash: str | None = None,
) -> dict:
    """
    Full DigiLocker-backed certificate verification with DID identity binding.
 
    Flow:
      1. Fetch user details → extract digilocker_id + verified name.
      2. bind_identity() → create-or-return the person's permanent identity_did.
      3. Fetch the DigiLocker document → extract cert_number.
      4. Require submitted_cert_hash — reject if absent.
      5. verify_by_cert_number() → HMAC + IPFS + Algorand checks.
      6. verify_identity_against_cert() → name_hash vs cert's issued_to.
      7. Revoke DigiLocker session.
      8. Return result with identity_did and composite government_verified flag.
    """
    from algorand_service import verify_by_cert_number
    from identity_service import bind_identity, verify_identity_against_cert
 
    # Step 1 ── user details + stable digilocker_id ───────────────────────────
    try:
        user_details = _get_digilocker_user_details(request_id)
    except Exception as exc:
        revoke_access(request_id)
        return {"valid": False, "reason": f"DigiLocker session fetch failed: {exc}"}
 
    # Setu returns a stable uid. Fall back to request_id in sandbox mode.
    digilocker_id   = user_details.get("id") or request_id
    digilocker_name = user_details.get("name", "").strip()
 
    if not digilocker_name:
        revoke_access(request_id)
        return {
            "valid":  False,
            "reason": "DigiLocker session did not return a verified name — consent may be incomplete",
        }
 
    # Step 2 ── bind identity → identity_did ──────────────────────────────────
    try:
        anchor = bind_identity(digilocker_id, digilocker_name)
    except Exception as exc:
        log.error("Identity binding failed: %s", exc)
        revoke_access(request_id)
        return {"valid": False, "reason": f"Identity binding failed: {exc}"}
 
    identity_did     = anchor["identity_did"]
    identity_created = anchor["created"]
 
    # Step 3 ── fetch document → cert_number ──────────────────────────────────
    try:
        doc = fetch_document_data(request_id, doc_type, org_id)
    except Exception as exc:
        revoke_access(request_id)
        return {
            "valid":        False,
            "identity_did": identity_did,
            "reason":       f"DigiLocker document fetch failed: {exc}",
        }
 
    cert_number = doc.get("cert_number", "").strip()
    if not cert_number:
        revoke_access(request_id)
        return {
            "valid":        False,
            "identity_did": identity_did,
            "reason":       "Could not extract cert/roll number from DigiLocker document",
            "detail":       "Check doc_type and org_id — field path may differ for this document type",
        }
 
    # Step 4 ── require submitted_cert_hash ───────────────────────────────────
    if not submitted_cert_hash:
        revoke_access(request_id)
        return {
            "valid":        False,
            "identity_did": identity_did,
            "reason":       "submitted_cert_hash is required — employer must upload the certificate image",
            "detail":       "This ensures the verifier physically holds the document, not just the cert number",
        }
 
    # Step 5 ── certificate + chain verification ───────────────────────────────
    result = verify_by_cert_number(
        cert_number=cert_number,
        submitted_cert_hash=submitted_cert_hash,
        digilocker_name=None,               # identity handled here, not in algorand_service
    )
 
    # Step 6 ── identity cross-check via DID anchor ────────────────────────────
    issued_to_hash    = result.pop("issued_to", None)
    identity_check    = verify_identity_against_cert(identity_did, issued_to_hash)
    identity_verified = identity_check["matched"]
 
    # Step 7 ── revoke session ─────────────────────────────────────────────────
    revoke_access(request_id)
 
    # Step 8 ── composite response ─────────────────────────────────────────────
    certificate_valid   = result.get("valid", False)
    government_verified = certificate_valid and identity_verified  # FIXED: derived not hardcoded
 
    return {
        **result,
        "identity_did":                identity_did,
        "identity_verified":           identity_verified,
        "identity_check":              identity_check["detail"],
        "identity_anchor_new":         identity_created,
        "cert_number_from_digilocker": cert_number,
        "source":                      "DigiLocker",
        "government_verified":         government_verified,
    }