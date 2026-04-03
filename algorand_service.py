from dotenv import load_dotenv
from algosdk import transaction  # account/mnemonic removed: private keys handled solely by signing_service
from algosdk.v2client import algod, indexer
from ipfs_service import pin_certificate_metadata,fetch_certificate_metadata,pin_with_retry
import os, json, base64, time
import sqlite3
from PIL import Image
import io
import hashlib
import hmac

# Security: all private-key operations are routed through signing_service.
# This module never holds or passes a raw private key.
from signing_service import sign_transaction, get_issuer_address


DB_PATH = "skillchain.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            cert_hash TEXT PRIMARY KEY,
            tx_id     TEXT NOT NULL,
            doc_type  TEXT,
            issued_at TEXT,
            ipfs_cid  TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_to_db(cert_hash, tx_id, doc_type, issued_at, ipfs_cid=None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO certificates VALUES (?, ?, ?, ?, ?)",
        (cert_hash, tx_id, doc_type, issued_at, ipfs_cid)  # ← now stored
    )
    conn.commit()
    conn.close()


def lookup_hash(cert_hash: str) -> str | None:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT tx_id FROM certificates WHERE cert_hash = ?",
        (cert_hash,)
    ).fetchone()
    conn.close()
    return row[0] if row else None

load_dotenv()

ALGOD_URL     = os.getenv("ALGOD_URL", "https://testnet-api.algonode.cloud")
INDEXER_URL   = os.getenv("INDEXER_URL", "https://testnet-idx.algonode.cloud")
ALGOD_TOKEN   = ""
INDEXER_TOKEN = ""

def get_algod_client():
    return algod.AlgodClient(ALGOD_TOKEN, ALGOD_URL)

def get_indexer_client():
    return indexer.IndexerClient(INDEXER_TOKEN, INDEXER_URL)


def anchor_hash(cert_hash: str, doc_type: str,
                institution: dict, signature: str,
                institution_id: str | None = None) -> dict:
    """
    Anchor a certificate hash on Algorand.

    Args:
        cert_hash:      SHA-256 hex digest of the normalised certificate.
        doc_type:       Document category string (e.g. "academic").
        institution:    Dict with at least "institution" and "did" keys.
        signature:      Ed25519 credential signature (base64).
        institution_id: Per-institution Vault/AES-GCM key ID.
                        None → legacy system wallet (wallet_version=1).

    Security: address and signing both routed through signing_service.
    No private key bytes enter this scope.
    """
    import logging
    log = logging.getLogger(__name__)

    if institution_id is not None:
        # Per-institution wallet (wallet_version=2)
        address       = get_issuer_address(institution_id)
        wallet_version = 2
    else:
        # Legacy shared system wallet — log a deprecation warning
        log.warning(
            "anchor_hash: issuing with legacy shared system wallet "
            "(institution_id not provided). "
            "Approve institution via /admin/approve/<id> to get a dedicated wallet."
        )
        address       = get_issuer_address()
        wallet_version = 1

    client    = get_algod_client()
    issued_at = time.strftime("%Y-%m-%d")

    # Build IPFS metadata — all the rich data lives here
    issued_by  = institution.get("institution") if isinstance(institution, dict) else str(institution)
    issuer_did = institution.get("did", "")     if isinstance(institution, dict) else ""
    metadata = {
        "version":   "1.0",
        "cert_hash": cert_hash,
        "doc_type":  doc_type,
        "issued_by": issued_by,
        "issuer_did": issuer_did,
        "issued_at": issued_at,
        "signature": signature,
    }

    ipfs_cid = pin_with_retry(metadata)

    # Note: CID + schema version + wallet_version ("wv") for verifier transparency.
    # institution_id is NOT stored here — it is derivable from the sender address.
    note_data  = {"sc": "1", "cid": ipfs_cid, "wv": wallet_version}
    note_bytes = json.dumps(note_data).encode()

    assert len(note_bytes) < 150, f"Unexpected note size: {len(note_bytes)}"

    params = client.suggested_params()
    txn = transaction.PaymentTxn(
        sender=address, sp=params,
        receiver=address, amt=0, note=note_bytes
    )

    # sign_transaction fetches the key from Vault/AES-GCM, signs, and deletes it.
    signed_txn = sign_transaction(txn, institution_id)
    tx_id      = client.send_transaction(signed_txn)
    transaction.wait_for_confirmation(client, tx_id, 4)

    save_to_db(cert_hash, tx_id, doc_type, issued_at, ipfs_cid)
    return {"tx_id": tx_id, "ipfs_cid": ipfs_cid, "wallet_version": wallet_version}

def verify_hash(cert_hash: str) -> dict:
    tx_id = lookup_hash(cert_hash)

    if tx_id:
        client   = get_indexer_client()
        txn      = client.transaction(tx_id).get("transaction", {})
        note_raw = txn.get("note", "")
        note     = json.loads(base64.b64decode(note_raw).decode())

        ipfs_cid = note.get("cid")
        if not ipfs_cid:
            return {"valid": False, "reason": "Malformed note — no CID"}

        meta = fetch_certificate_metadata(ipfs_cid)

        if meta.get("cert_hash") != cert_hash:
            return {"valid": False, "reason": "IPFS hash mismatch — data tampered"}

        # Use actual sender from the Algorand transaction (not the system address)
        sender_address = txn.get("sender", "")

        # Check revocation and wallet_version from did_registry
        conn = sqlite3.connect(DB_PATH)
        reg_row = conn.execute(
            """
            SELECT wallet_version, revoked, institution_id
            FROM did_registry
            WHERE institution_address = ?
               OR (institution_address IS NULL AND address = ?)
            """,
            (sender_address, sender_address),
        ).fetchone()
        conn.close()

        if reg_row and reg_row[1] == 1:   # revoked
            return {"valid": False, "reason": "issuer_revoked"}

        # wallet_version: prefer DB column; fall back to note field; default to 1
        wallet_version = (
            reg_row[0] if reg_row and reg_row[0] is not None
            else note.get("wv", 1)
        )

        from did_service import verify_provenance
        provenance = verify_provenance(
            sender_address,
            cert_hash,
            meta.get("signature", ""),
        )

        return {
            "valid":           True,
            "signature_valid": provenance.get("verified"),
            "wallet_version":  wallet_version,
            "tx_id":           txn["id"],
            "confirmed_round": txn["confirmed-round"],
            "issued_by":       meta.get("issued_by"),
            "issuer_did":      meta.get("issuer_did"),
            "doc_type":        meta.get("doc_type"),
            "issued_at":       meta.get("issued_at"),
            "ipfs_cid":        ipfs_cid,
            "ipfs_url":        f"https://gateway.pinata.cloud/ipfs/{ipfs_cid}",
            "explorer_url":    f"https://testnet.explorer.perawallet.app/tx/{txn['id']}",
        }

    return _verify_via_indexer(cert_hash)


def _verify_via_indexer(cert_hash: str) -> dict:
    client = get_indexer_client()
    # Security: only the public address is needed for indexer lookup
    address = get_issuer_address()
    try:
        txns = client.search_transactions(
            address=address,
            note_prefix=b'{"sc":'      # matches new note format
        ).get("transactions", [])

        for txn in txns:
            note_raw = txn.get("note", "")
            try:
                note = json.loads(base64.b64decode(note_raw).decode())
                ipfs_cid = note.get("cid")
                if not ipfs_cid:
                    continue
                
                # Fetch from IPFS and check cert_hash
                meta = fetch_certificate_metadata(ipfs_cid)
                if meta.get("cert_hash") == cert_hash:
                    return {
                        "valid": True,
                        "tx_id": txn["id"],
                        "confirmed_round": txn["confirmed-round"],
                        "issued_by": meta.get("issued_by"),
                        "doc_type": meta.get("doc_type"),
                        "issued_at": meta.get("issued_at"),
                        "ipfs_cid": ipfs_cid,
                        "source": "algorand_indexer_fallback",
                        "explorer_url": f"https://testnet.explorer.perawallet.app/tx/{txn['id']}"
                    }
            except Exception:
                continue
    except Exception as e:
        return {"valid": False, "reason": f"Indexer error: {str(e)}"}

    return {"valid": False, "reason": "Certificate not found"}

def get_anchored_name_hash(cert_hash: str) -> str:
    tx_id = lookup_hash(cert_hash)
    if not tx_id:
        return ""
    
    client = get_indexer_client()
    response = client.transaction(tx_id)
    txn = response.get("transaction", {})
    
    note_raw = txn.get("note", "")
    note_decoded = base64.b64decode(note_raw).decode()
    note_json = note_decoded.replace("skillchain:j", "")
    data = json.loads(note_json)
    
    return data.get("name_hash", "")

if __name__ == "__main__":
    init_db()
    address = get_issuer_address()
    print(f"Wallet ready: {address}")
    print("DB initialised.")