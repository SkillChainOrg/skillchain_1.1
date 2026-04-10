"""
algorand_service.py — Algorand anchoring and verification for SkillChain.

CHANGES (PostgreSQL migration):
  - Removed sqlite3 / DB_PATH.
  - All DB access uses psycopg2 via db.get_db_connection() / db.dict_cursor().
  - SQL placeholders changed from ? to %s.
  - INSERT OR REPLACE → INSERT ... ON CONFLICT (cert_hash) DO UPDATE SET ...
  - Row access changed from positional index to dict keys.
  - Added explicit cursor management (cur = conn.cursor()).
"""

import base64
import hashlib
import hmac as hmac_lib
import json
import logging
import os
import secrets
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

HMAC_SECRET = os.getenv("HMAC_SECRET")
if not HMAC_SECRET:
    raise RuntimeError(
        "HMAC_SECRET is not set. Add it to your .env file.\n"
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )

ALGOD_URL     = os.getenv("ALGOD_URL",   "https://testnet-api.algonode.cloud")
INDEXER_URL   = os.getenv("INDEXER_URL", "https://testnet-idx.algonode.cloud")
ALGOD_TOKEN   = ""
INDEXER_TOKEN = ""


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
    issued_to: str | None = None,
) -> None:
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

def generate_hmac(cert_hash: str) -> str:
    """
    Return HMAC-SHA256(HMAC_SECRET, cert_hash) as a hex string.

    The secret is loaded once from the environment at module startup.
    Never stored in the DB — recomputed on demand for verification.
    """
    return hmac_lib.new(
        HMAC_SECRET.encode(), cert_hash.encode(), hashlib.sha256
    ).hexdigest()


# ── Core: anchor a certificate hash on Algorand ───────────────────────────────

def anchor_hash(
    cert_hash: str,
    doc_type: str,
    institution: dict,
    signature: str,
    institution_id: str | None = None,
    cert_number: str | None = None,
    issued_to: str | None = None,
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
        issued_to:      SHA-256 hash of the holder's name (name.strip().lower()).
                        NOT the raw name — keeps PII out of the DB and IPFS.

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

    hmac_value = generate_hmac(cert_hash)

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
        "issued_to":   issued_to or "",
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
      3. Re-compute HMAC from stored key; compare with IPFS-stored value.
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
    # Always recompute from the stored cert_hash using the server-side secret.
    # Never trust user-submitted values for this comparison.
    hmac_ok = False
    if stored_hmac_value:
        recomputed = generate_hmac(cert_hash)
        ipfs_hmac  = meta.get("hmac_value", "")
        hmac_ok    = (
            hmac_lib.compare_digest(recomputed, stored_hmac_value)
            and hmac_lib.compare_digest(recomputed, ipfs_hmac)
        )

    # ── Revocation check (PostgreSQL) ──────────────────────────────────────
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
    digilocker_name: str | None = None,
) -> dict:
    """
    Verify a certificate using its roll/certificate number.

    Args:
        cert_number:           Roll/certificate number from the DigiLocker document.
        submitted_cert_hash:   SHA-256 of the certificate image submitted by employer.
        digilocker_name:       Name as returned by DigiLocker (optional).

    Returns:
        dict with valid, identity_verified, and full verification detail.
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
    issued_to        = row["issued_to"]

    # Guard: only do image-match when a hash was actually submitted.
    # An empty string will never match a SHA-256 hash, so we check explicitly.
    if submitted_cert_hash and submitted_cert_hash != stored_cert_hash:
        return {
            "valid":  False,
            "reason": "Certificate image does not match the issued certificate",
            "detail": "The submitted file has been modified or is not the original",
        }

    result = _verify_full(stored_cert_hash, tx_id, ipfs_cid, hmac_value)
    if not result.get("valid"):
        return result

    # Pass issued_to up to the identity layer (identity_service.verify_identity_against_cert).
    # Identity verification is no longer done inline here — the DID-bound identity
    # anchor is the authoritative check.  digilocker_name is accepted for back-compat
    # but ignored when identity_service is in use.
    return {
        **result,
        "issued_to": issued_to,         # consumed by identity_service
        "source":    "digilocker_cert_number_lookup",
    }


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    address = get_issuer_address()
    print(f"Wallet ready: {address}")
    print("DB initialised.")