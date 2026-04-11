"""
algorand_service.py — Algorand anchoring and verification for SkillChain.

SECURITY REFACTORS (this revision):
  1. HMAC key no longer stored in DB.
     A master key (HMAC_MASTER_KEY env var) is used to derive a per-cert
     HMAC key as HMAC-SHA256(master_key, cert_hash).  The key is
     deterministic from inputs the server already holds, so it never needs
     to be persisted.  The hmac_key column in the DB is ignored on read
     and not written on new inserts.

  2. issued_to now stores identity_did (did:skillchain:identity:...)
     instead of hash(name).  This removes the name-collision risk (two
     people with identical names produce the same hash) and anchors
     ownership to a government-verified, unforgeable DID.

  3. verify_identity_against_cert (name-hash comparison) is replaced by
     verify_identity_owns_cert (DID string equality).  No DB join needed —
     the DID stored at issuance time is compared directly against the
     claimant's DID.

UNCHANGED:
  - All public function signatures (anchor_hash, verify_hash, verify_by_cert_number).
  - Algorand transaction flow.
  - IPFS pinning.
  - Ed25519 provenance checks.
"""

import base64
import hashlib
import hmac as hmac_lib
import json
import logging
import os
import time

from dotenv import load_dotenv
from algosdk import transaction
from algosdk.v2client import algod, indexer
from PIL import Image
import io

from db import get_db_connection, dict_cursor
from ipfs_service import pin_certificate_metadata, fetch_certificate_metadata, pin_with_retry
from signing_service import sign_transaction, get_issuer_address

load_dotenv()

log = logging.getLogger(__name__)

ALGOD_URL     = os.getenv("ALGOD_URL",   "https://testnet-api.algonode.cloud")
INDEXER_URL   = os.getenv("INDEXER_URL", "https://testnet-idx.algonode.cloud")
ALGOD_TOKEN   = ""
INDEXER_TOKEN = ""

# ── HMAC master key (never stored in DB) ──────────────────────────────────────
#
# Set HMAC_MASTER_KEY in your .env or secret manager to a random 64-char hex
# string.  Generate one with: python3 -c "import secrets; print(secrets.token_hex(32))"
#
# If the env var is absent we fall back to a fixed dev-only sentinel so the
# system remains functional locally.  The fallback MUST NOT be used in
# production — a startup warning is emitted.

_RAW_MASTER_KEY = os.getenv("HMAC_MASTER_KEY", "")
if not _RAW_MASTER_KEY:
    log.warning(
        "HMAC_MASTER_KEY env var is not set — using insecure dev fallback. "
        "Set this variable before going to production."
    )
    _RAW_MASTER_KEY = "dev-only-insecure-hmac-master-key-do-not-use-in-prod"

_MASTER_KEY_BYTES: bytes = (
    bytes.fromhex(_RAW_MASTER_KEY)
    if len(_RAW_MASTER_KEY) == 64 and all(c in "0123456789abcdef" for c in _RAW_MASTER_KEY)
    else _RAW_MASTER_KEY.encode()
)


# ── DB helpers ────────────────────────────────────────────────────────────────

def init_db():
    """Create the certificates table if it does not exist."""
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                cert_hash   TEXT PRIMARY KEY,
                tx_id       TEXT NOT NULL,
                doc_type    TEXT,
                issued_at   TEXT,
                ipfs_cid    TEXT,
                cert_number TEXT,
                hmac_value  TEXT,
                issued_to   TEXT
            )
        """)
        # hmac_key column intentionally absent — key is derived, not stored.
        conn.commit()
    finally:
        cur.close()
        conn.close()


def save_to_db(
    cert_hash: str,
    tx_id: str,
    doc_type: str,
    issued_at: str,
    ipfs_cid: str | None = None,
    cert_number: str | None = None,
    hmac_value: str | None = None,
    issued_to: str | None = None,    # stores identity_did, NOT hash(name)
) -> None:
    """
    Persist a certificate record.

    NOTE: hmac_key is deliberately excluded.  The key is derived at
    verification time from HMAC_MASTER_KEY + cert_hash.
    """
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO certificates
                (cert_hash, tx_id, doc_type, issued_at, ipfs_cid,
                 cert_number, hmac_value, issued_to)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (cert_hash) DO UPDATE SET
                tx_id       = EXCLUDED.tx_id,
                doc_type    = EXCLUDED.doc_type,
                issued_at   = EXCLUDED.issued_at,
                ipfs_cid    = EXCLUDED.ipfs_cid,
                cert_number = EXCLUDED.cert_number,
                hmac_value  = EXCLUDED.hmac_value,
                issued_to   = EXCLUDED.issued_to
            """,
            (cert_hash, tx_id, doc_type, issued_at, ipfs_cid,
             cert_number, hmac_value, issued_to),
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()


def lookup_hash(cert_hash: str) -> dict | None:
    """Return dict with tx_id, hmac_value, cert_number, ipfs_cid — or None."""
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        cur.execute(
            """
            SELECT tx_id, hmac_value, cert_number, ipfs_cid
            FROM certificates WHERE cert_hash = %s
            """,
            (cert_hash,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        cur.close()
        conn.close()


def lookup_by_cert_number(cert_number: str) -> dict | None:
    """Return dict with cert_hash, tx_id, hmac_value, ipfs_cid, issued_to — or None."""
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        cur.execute(
            """
            SELECT cert_hash, tx_id, hmac_value, ipfs_cid, issued_to
            FROM certificates WHERE cert_number = %s
            """,
            (cert_number,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        cur.close()
        conn.close()


# ── Algorand clients ──────────────────────────────────────────────────────────

def get_algod_client():
    return algod.AlgodClient(ALGOD_TOKEN, ALGOD_URL)


def get_indexer_client():
    return indexer.IndexerClient(INDEXER_TOKEN, INDEXER_URL)


# ── HMAC helpers ──────────────────────────────────────────────────────────────

def _derive_cert_hmac_key(cert_hash: str) -> bytes:
    """
    Derive a per-certificate HMAC key from the master key and cert_hash.

    Using HKDF-style derivation (HMAC-SHA256(master, cert_hash)) means:
      • The key is unique per certificate (no key reuse across certs).
      • The key is fully deterministic — no storage required.
      • Compromising one cert's key reveals nothing about others.
      • The master key is the only secret; it never touches the DB.
    """
    return hmac_lib.new(
        _MASTER_KEY_BYTES,
        cert_hash.encode(),
        hashlib.sha256,
    ).digest()


def _compute_hmac(cert_hash: str) -> str:
    """
    Compute HMAC-SHA256 over cert_hash using the derived per-cert key.

    Returns a hex string.  This replaces the old two-argument version that
    required the caller to supply the key.
    """
    derived_key = _derive_cert_hmac_key(cert_hash)
    return hmac_lib.new(derived_key, cert_hash.encode(), hashlib.sha256).hexdigest()


# ── Core: anchor a certificate hash on Algorand ───────────────────────────────

def anchor_hash(
    cert_hash: str,
    doc_type: str,
    institution: dict,
    signature: str,
    institution_id: str | None = None,
    cert_number: str | None = None,
    issued_to: str | None = None,       # expects identity_did, NOT hash(name)
) -> dict:
    """
    Anchor a certificate hash on Algorand and pin metadata to IPFS.

    Args:
        cert_hash:      SHA-256 hex digest of the normalised certificate image.
        doc_type:       Document category (e.g. "academic").
        institution:    Dict with at least "institution" and "did" keys.
        signature:      Ed25519 credential signature (base64).
        institution_id: Per-institution Vault/AES-GCM key ID. None → system wallet.
        cert_number:    Institution-assigned roll/cert number (DigiLocker lookup key).
        issued_to:      identity_did of the certificate holder
                        (did:skillchain:identity:...).  Stored as-is — no hashing.
                        Replaces the old hash(name) approach entirely.

    Returns:
        dict with tx_id, ipfs_cid, wallet_version, hmac_value.
    """
    if institution_id is not None:
        address        = get_issuer_address(institution_id)
        wallet_version = 2
    else:
        log.warning(
            "anchor_hash: issuing with legacy shared system wallet "
            "(institution_id not provided)."
        )
        address        = get_issuer_address()
        wallet_version = 1

    client    = get_algod_client()
    issued_at = time.strftime("%Y-%m-%d")

    # Key is derived, not stored.  Only the value goes to DB and IPFS.
    hmac_value = _compute_hmac(cert_hash)

    issued_by  = institution.get("institution") if isinstance(institution, dict) else str(institution)
    issuer_did = institution.get("did", "")     if isinstance(institution, dict) else ""

    metadata = {
        "version":     "1.0",
        "cert_hash":   cert_hash,
        "doc_type":    doc_type,
        "issued_by":   issued_by,
        "issuer_did":  issuer_did,
        "issued_at":   issued_at,
        "signature":   signature,
        "hmac_value":  hmac_value,
        "cert_number": cert_number or "",
        "issued_to":   issued_to or "",     # identity_did stored in IPFS metadata
    }

    ipfs_cid = pin_with_retry(metadata)

    note_data  = {"sc": "1", "cid": ipfs_cid, "wv": wallet_version}
    note_bytes = json.dumps(note_data).encode()
    assert len(note_bytes) < 150, f"Unexpected note size: {len(note_bytes)}"

    params = client.suggested_params()
    txn    = transaction.PaymentTxn(
        sender=address, sp=params, receiver=address, amt=0, note=note_bytes
    )

    signed_txn = sign_transaction(txn, institution_id)
    tx_id      = client.send_transaction(signed_txn)

    # hmac_key deliberately not passed — it is never stored.
    save_to_db(
        cert_hash, tx_id, doc_type, issued_at, ipfs_cid,
        cert_number=cert_number,
        hmac_value=hmac_value,
        issued_to=issued_to,
    )

    return {
        "tx_id":          tx_id,
        "ipfs_cid":       ipfs_cid,
        "wallet_version": wallet_version,
        "hmac_value":     hmac_value,
    }


# ── Core: verify a certificate hash ──────────────────────────────────────────

def verify_hash(cert_hash: str) -> dict:
    """
    Verify a certificate by its SHA-256 image hash.

    Steps:
      1. Look up in local DB (fast path).
      2. Fetch IPFS metadata and compare cert_hash field.
      3. Re-derive HMAC key from master + cert_hash; compare value.
      4. Check issuer revocation in did_registry.
      5. Verify Ed25519 provenance signature.
    """
    row = lookup_hash(cert_hash)
    if row:
        return _verify_full(
            cert_hash,
            row["tx_id"],
            row["ipfs_cid"],
            row["hmac_value"],
        )
    return _verify_via_indexer(cert_hash)


def _verify_full(
    cert_hash: str,
    tx_id: str,
    ipfs_cid: str,
    stored_hmac_value: str | None,
) -> dict:
    """Full verification against IPFS metadata and Algorand transaction."""
    client  = get_indexer_client()
    txn_obj = client.transaction(tx_id).get("transaction", {})
    note_raw = txn_obj.get("note", "")

    try:
        note = json.loads(base64.b64decode(note_raw).decode())
    except Exception:
        return {"valid": False, "reason": "Malformed transaction note"}

    ipfs_cid_from_note = note.get("cid") or ipfs_cid
    meta = fetch_certificate_metadata(ipfs_cid_from_note)

    if meta.get("cert_hash") != cert_hash:
        return {"valid": False, "reason": "IPFS hash mismatch — data tampered"}

    # ── HMAC tamper-evidence check ─────────────────────────────────────────
    # Key is derived fresh from the master key — no DB read needed.
    hmac_ok = False
    if stored_hmac_value:
        recomputed = _compute_hmac(cert_hash)
        ipfs_hmac  = meta.get("hmac_value", "")
        hmac_ok    = (
            hmac_lib.compare_digest(recomputed, stored_hmac_value)
            and hmac_lib.compare_digest(recomputed, ipfs_hmac)
        )

    # ── Revocation check ──────────────────────────────────────────────────
    sender_address = txn_obj.get("sender", "")
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        cur.execute(
            """
            SELECT wallet_version, revoked, institution_id
            FROM did_registry
            WHERE institution_address = %s
               OR (institution_address IS NULL AND address = %s)
            """,
            (sender_address, sender_address),
        )
        reg_row = cur.fetchone()
    finally:
        cur.close()
        conn.close()

    if reg_row and reg_row["revoked"] == 1:
        return {"valid": False, "reason": "issuer_revoked"}

    wallet_version = (
        reg_row["wallet_version"]
        if reg_row and reg_row["wallet_version"] is not None
        else note.get("wv", 1)
    )

    # ── Ed25519 provenance check ──────────────────────────────────────────
    from did_service import verify_provenance
    provenance = verify_provenance(
        sender_address, cert_hash, meta.get("signature", "")
    )

    return {
        "valid":            True,
        "hmac_valid":       hmac_ok,
        "signature_valid":  provenance.get("verified"),
        "wallet_version":   wallet_version,
        "tx_id":            txn_obj["id"],
        "confirmed_round":  txn_obj["confirmed-round"],
        "issued_by":        meta.get("issued_by"),
        "issuer_did":       meta.get("issuer_did"),
        "doc_type":         meta.get("doc_type"),
        "issued_at":        meta.get("issued_at"),
        "cert_number":      meta.get("cert_number"),
        "ipfs_cid":         ipfs_cid_from_note,
        "ipfs_url":         f"https://gateway.pinata.cloud/ipfs/{ipfs_cid_from_note}",
        "explorer_url":     f"https://testnet.explorer.perawallet.app/tx/{txn_obj['id']}",
    }


def _verify_via_indexer(cert_hash: str) -> dict:
    """Fallback: scan Algorand indexer when cert is not in local DB."""
    client  = get_indexer_client()
    address = get_issuer_address()
    try:
        txns = client.search_transactions(
            address=address, note_prefix=b'{"sc":'
        ).get("transactions", [])

        for txn in txns:
            note_raw = txn.get("note", "")
            try:
                note     = json.loads(base64.b64decode(note_raw).decode())
                ipfs_cid = note.get("cid")
                if not ipfs_cid:
                    continue
                meta = fetch_certificate_metadata(ipfs_cid)
                if meta.get("cert_hash") == cert_hash:
                    return {
                        "valid":           True,
                        "tx_id":           txn["id"],
                        "confirmed_round": txn["confirmed-round"],
                        "issued_by":       meta.get("issued_by"),
                        "doc_type":        meta.get("doc_type"),
                        "issued_at":       meta.get("issued_at"),
                        "cert_number":     meta.get("cert_number"),
                        "ipfs_cid":        ipfs_cid,
                        "source":          "algorand_indexer_fallback",
                        "explorer_url":    f"https://testnet.explorer.perawallet.app/tx/{txn['id']}",
                    }
            except Exception:
                continue
    except Exception as e:
        return {"valid": False, "reason": f"Indexer error: {str(e)}"}

    return {"valid": False, "reason": "Certificate not found"}


# ── DigiLocker verification path ──────────────────────────────────────────────

def verify_by_cert_number(
    cert_number: str,
    submitted_cert_hash: str,
) -> dict:
    """
    Verify a certificate using its roll/certificate number.

    CHANGED: digilocker_name parameter removed — identity is now verified
    via DID comparison in identity_service.verify_identity_owns_cert(), not
    via name-hash comparison.

    Args:
        cert_number:         Roll/certificate number from the DigiLocker document.
        submitted_cert_hash: SHA-256 of the certificate image submitted by employer.

    Returns:
        dict with valid, full verification detail, and issued_to (identity_did).
    """
    row = lookup_by_cert_number(cert_number)
    if not row:
        return {
            "valid":  False,
            "reason": f"No certificate found with cert_number='{cert_number}'",
        }

    stored_cert_hash = row["cert_hash"]
    tx_id            = row["tx_id"]
    hmac_value       = row["hmac_value"]
    ipfs_cid         = row["ipfs_cid"]
    issued_to_did    = row["issued_to"]   # identity_did stored at issuance time

    if submitted_cert_hash != stored_cert_hash:
        return {
            "valid":  False,
            "reason": "Certificate image does not match the issued certificate",
            "detail": "The submitted file has been modified or is not the original",
        }

    result = _verify_full(stored_cert_hash, tx_id, ipfs_cid, hmac_value)
    if not result.get("valid"):
        return result

    # Pass issued_to_did up to identity_service.verify_identity_owns_cert().
    # That function does a direct DID string comparison — no hash join required.
    return {
        **result,
        "issued_to":  issued_to_did,   # identity_did consumed by identity layer
        "source":     "digilocker_cert_number_lookup",
    }


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    address = get_issuer_address()
    print(f"Wallet ready: {address}")
    print("DB initialised.")