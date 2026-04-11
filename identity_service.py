"""
identity_service.py — DigiLocker-to-DID identity binding for SkillChain.

SECURITY REFACTORS (this revision):
  1. hash_name() is now PUBLIC.
     All callers (app.py issuance routes, this module) use a single function.
     The old inline hashlib.sha256(name.strip().lower().encode()).hexdigest()
     scattered across app.py is gone — one canonical implementation, one place.

  2. verify_identity_against_cert() REPLACED by verify_identity_owns_cert().
     Old approach: fetch name_hash from identity_anchors, compare with
     cert's issued_to hash.  Brittle because:
       • Two people with the same name produce the same issued_to hash.
       • Requires a DB round-trip to get name_hash.
       • Mixes hashing logic across two tables.

     New approach: issued_to stores identity_did directly (a unique DID,
     not a name hash).  Verification is a constant-time DID string comparison —
     no DB lookup, no hash collision risk.

Architecture (Option 3 — full identity anchor):

  DigiLocker authenticates a person
          ↓
  We create/lookup an identity_anchor row:
      identity_did  = did:skillchain:identity:<16-char-hash>
      name_hash     = SHA-256(normalised name)   ← never store raw name
      digilocker_id = opaque user ID from DigiLocker
      bound_at      = timestamp
          ↓
  At issuance time the identity_did is stored in certificates.issued_to.

  At verification time:
      DigiLocker confirms user is "X"  → their identity_did is looked up
          ↓
      certificates.issued_to == claimant's identity_did ?
          ↓
      Return: certificate_valid + identity_verified + identity_did
"""

import hashlib
import hmac as hmac_lib
import logging
import time

from db import get_db_connection, dict_cursor

log = logging.getLogger(__name__)

DID_METHOD = "did:skillchain:identity"


# ── Canonical name operations ─────────────────────────────────────────────────
#
# SINGLE SOURCE OF TRUTH for all name normalisation and hashing in SkillChain.
# Import hash_name from here; never inline hashlib.sha256(name...) elsewhere.

def normalize_name(name: str) -> str:
    """Canonical normalisation: strip surrounding whitespace, lowercase."""
    return name.strip().lower()


def hash_name(name: str) -> str:
    """
    SHA-256 of the normalised name.

    Used to store names in the DB without retaining raw PII.
    All callers — issuance, identity binding, test code — must use this
    function.  Do not inline hashlib.sha256(name.strip().lower()...) anywhere.
    """
    return hashlib.sha256(normalize_name(name).encode()).hexdigest()


# ── DID derivation ────────────────────────────────────────────────────────────

def _derive_identity_did(digilocker_id: str, name_hash: str) -> str:
    """
    Derive a stable, deterministic DID for a person.

    Combines the DigiLocker user ID (opaque, from Setu) with the name_hash
    so the DID is unique per (person × DigiLocker account).

    NOT reversible — no raw name or ID is recoverable from the DID.
    """
    seed   = f"{digilocker_id}:{name_hash}"
    suffix = hashlib.sha256(seed.encode()).hexdigest()[:16]
    return f"{DID_METHOD}:{suffix}"


# ── DB operations ─────────────────────────────────────────────────────────────

def bind_identity(digilocker_id: str, digilocker_name: str) -> dict:
    """
    Create or return the identity anchor for a DigiLocker-authenticated user.

    Called after a successful DigiLocker consent flow.  Idempotent — calling
    it twice for the same digilocker_id returns the same identity_did.

    Args:
        digilocker_id:   Opaque user identifier from DigiLocker.
        digilocker_name: Government-verified name from the DigiLocker session.

    Returns:
        dict with identity_did, name_hash, created (bool).
    """
    if not digilocker_id or not digilocker_name:
        raise ValueError("digilocker_id and digilocker_name are required to bind identity")

    # Use the canonical function — not an inline hash.
    name_h       = hash_name(digilocker_name)
    identity_did = _derive_identity_did(digilocker_id, name_h)

    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
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

        cur.execute(
            """
            INSERT INTO identity_anchors
                (identity_did, digilocker_id, name_hash, bound_at)
            VALUES (%s, %s, %s, %s)
            """,
            (identity_did, digilocker_id, name_h, time.strftime("%Y-%m-%dT%H:%M:%SZ")),
        )
        conn.commit()
        log.info("Identity anchor created: %s", identity_did)
        return {
            "identity_did": identity_did,
            "name_hash":    name_h,
            "created":      True,
        }
    finally:
        cur.close()
        conn.close()


def lookup_identity(digilocker_id: str) -> dict | None:
    """
    Look up an existing identity anchor by DigiLocker user ID.

    Returns None if no anchor exists.
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


# ── Identity verification ─────────────────────────────────────────────────────

def verify_identity_owns_cert(claimant_did: str, cert_issued_to_did: str | None) -> dict:
    """
    Confirm that a certificate was issued to the given identity DID.

    REPLACES verify_identity_against_cert (name-hash comparison).

    The certificates.issued_to column now stores an identity_did directly.
    Ownership verification is therefore a constant-time string comparison —
    no DB lookup, no hash collision risk, no cross-table join.

    Args:
        claimant_did:      The identity_did of the person claiming ownership.
                           Comes from a fresh DigiLocker bind (bind_identity).
        cert_issued_to_did: The identity_did stored in the certificate at issuance.
                            None means the certificate was issued without identity binding.

    Returns:
        dict with:
            matched (bool)   — True if the DIDs match
            detail  (str)    — human-readable explanation
    """
    if not cert_issued_to_did:
        return {
            "matched": False,
            "detail":  "Certificate has no identity binding — issued_to is empty",
        }

    # Constant-time comparison prevents timing-oracle attacks.
    matched = hmac_lib.compare_digest(claimant_did, cert_issued_to_did)
    return {
        "matched": matched,
        "detail":  (
            "DigiLocker-verified identity matches certificate holder"
            if matched
            else "DigiLocker identity does NOT match certificate holder"
        ),
    }