"""
identity_service.py — DigiLocker-to-DID identity binding for SkillChain.
 
Architecture (Option 3 — full identity anchor):
 
  DigiLocker authenticates a person
          ↓
  We create/lookup an identity_anchor row:
      identity_did  = did:skillchain:identity:<16-char-hash>
      name_hash     = SHA-256(normalised name)   ← never store raw name
      digilocker_id = opaque user ID from Setu
      bound_at      = timestamp
          ↓
  The identity_did becomes the persistent reference for this person
  across all certificate verifications — decoupled from any single cert.
 
  At verification time:
      DigiLocker confirms user is "X"
          ↓
      Lookup identity anchor by digilocker_id → get identity_did
          ↓
      Compare anchor's name_hash with cert's issued_to hash
          ↓
      Return: certificate_valid + identity_verified + identity_did
 
This means:
  - Identity is government-rooted (DigiLocker / Aadhaar-backed)
  - Identity is portable across certificates (one DID, many certs)
  - No raw PII ever touches our DB
"""
 
import hashlib
import logging
import time
 
from db import get_db_connection, dict_cursor
 
log = logging.getLogger(__name__)
 
DID_METHOD = "did:skillchain:identity"
 
 
# ── DID derivation ────────────────────────────────────────────────────────────
 
def _derive_identity_did(digilocker_id: str, name_hash: str) -> str:
    """
    Derive a stable, deterministic DID for a person.
 
    Combines the DigiLocker user ID (opaque, from Setu) with the name_hash
    so the DID is unique per (person × DigiLocker account).
 
    NOT reversible — no raw name or ID is recoverable from the DID.
    """
    seed = f"{digilocker_id}:{name_hash}"
    suffix = hashlib.sha256(seed.encode()).hexdigest()[:16]
    return f"{DID_METHOD}:{suffix}"
 
 
def _normalize_name(name: str) -> str:
    return name.strip().lower()
 
 
def _hash_name(name: str) -> str:
    return hashlib.sha256(_normalize_name(name).encode()).hexdigest()
 
 
# ── DB operations ─────────────────────────────────────────────────────────────
 
def bind_identity(digilocker_id: str, digilocker_name: str) -> dict:
    """
    Create or return the identity anchor for a DigiLocker-authenticated user.
 
    Called after a successful DigiLocker consent flow.  Idempotent — calling
    it twice for the same digilocker_id returns the same identity_did.
 
    Args:
        digilocker_id:   Opaque user identifier from Setu (e.g. DigiLocker UID).
        digilocker_name: Government-verified name from DigiLocker session.
 
    Returns:
        dict with identity_did, name_hash, created (bool).
    """
    if not digilocker_id or not digilocker_name:
        raise ValueError("digilocker_id and digilocker_name are required to bind identity")
 
    name_hash    = _hash_name(digilocker_name)
    identity_did = _derive_identity_did(digilocker_id, name_hash)
 
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        # Check for existing anchor
        cur.execute(
            "SELECT identity_did, name_hash FROM identity_anchors WHERE digilocker_id = %s",
            (digilocker_id,),
        )
        existing = cur.fetchone()
 
        if existing:
            log.info("Identity anchor found: %s", existing["identity_did"])
            return {
                "identity_did": existing["identity_did"],
                "name_hash":    existing["name_hash"],
                "created":      False,
            }
 
        # Create new anchor
        cur.execute(
            """
            INSERT INTO identity_anchors
                (identity_did, digilocker_id, name_hash, bound_at)
            VALUES (%s, %s, %s, %s)
            """,
            (identity_did, digilocker_id, name_hash, time.strftime("%Y-%m-%dT%H:%M:%SZ")),
        )
        conn.commit()
        log.info("Identity anchor created: %s", identity_did)
        return {
            "identity_did": identity_did,
            "name_hash":    name_hash,
            "created":      True,
        }
    finally:
        cur.close()
        conn.close()
 
 
def lookup_identity(digilocker_id: str) -> dict | None:
    """
    Look up an existing identity anchor by DigiLocker user ID.
 
    Returns None if no anchor exists (user has never completed a DigiLocker
    consent flow through SkillChain before).
    """
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        cur.execute(
            "SELECT identity_did, name_hash, bound_at FROM identity_anchors WHERE digilocker_id = %s",
            (digilocker_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        cur.close()
        conn.close()
 
 
def verify_identity_against_cert(identity_did: str, issued_to_hash: str | None) -> dict:
    """
    Check whether an identity anchor's name_hash matches a certificate's issued_to field.
 
    Args:
        identity_did:   The DID of the person claiming ownership.
        issued_to_hash: SHA-256 of the holder's name stored at issuance time.
                        None means the certificate was issued without identity binding.
 
    Returns:
        dict with:
            matched (bool)      — True if the hashes match
            detail  (str)       — human-readable explanation
    """
    if not issued_to_hash:
        return {
            "matched": False,
            "detail":  "Certificate was issued without identity binding — cannot verify ownership",
        }
 
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        cur.execute(
            "SELECT name_hash FROM identity_anchors WHERE identity_did = %s",
            (identity_did,),
        )
        row = cur.fetchone()
    finally:
        cur.close()
        conn.close()
 
    if not row:
        return {
            "matched": False,
            "detail":  f"No identity anchor found for DID {identity_did}",
        }
 
    import hmac as hmac_lib
    matched = hmac_lib.compare_digest(row["name_hash"], issued_to_hash)
    return {
        "matched": matched,
        "detail":  (
            "DigiLocker-verified identity matches certificate holder"
            if matched
            else "DigiLocker identity does NOT match certificate holder — possible fraud"
        ),
    }