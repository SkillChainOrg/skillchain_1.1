from dotenv import load_dotenv
from algosdk import account, mnemonic as mn, transaction
from algosdk.v2client import algod, indexer
from ipfs_service import pin_certificate_metadata
import os, json, base64, time
import sqlite3
from PIL import Image
import io
import hashlib
import hmac


DB_PATH = "skillchain.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            cert_hash TEXT PRIMARY KEY,
            tx_id     TEXT NOT NULL,
            doc_type  TEXT,
            issued_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_to_db(cert_hash, tx_id, doc_type, issued_at, ipfs_cid=None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO certificates VALUES (?, ?, ?, ?)",
        (cert_hash, tx_id, doc_type, issued_at)
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

def load_wallet():
    phrase = os.getenv("MNEMONIC")
    if not phrase:
        raise ValueError("MNEMONIC not set in .env")
    private_key = mn.to_private_key(phrase)
    address = account.address_from_private_key(private_key)
    return private_key, address

def anchor_hash(cert_hash: str, doc_type: str, holder_name: str,
                institution: dict, signature: str) -> dict:
    private_key, address = load_wallet()
    client = get_algod_client()
    issued_at = time.strftime("%Y-%m-%d")

    name_hash = hmac.new(
        os.environ["NAME_HMAC_KEY"].encode(),
        holder_name.strip().lower().encode(),
        hashlib.sha256
    ).hexdigest() if holder_name else ""

    # Build the metadata — no PII
    metadata = {
        "version": "1.0",
        "cert_hash": cert_hash,
        "doc_type": doc_type,
        "issued_by": institution["institution"],
        "issuer_did": institution["did"],
        "issued_at": issued_at,
        "name_hash": name_hash,
        "signature": signature
    }

    # Pin to IPFS first, get CID
    ipfs_cid = pin_certificate_metadata(metadata)

    # Anchor CID + hash on Algorand
    note_data = {
        "sc": "1.0",           # skillchain version marker
        "hash": cert_hash,
        "cid": ipfs_cid,       # NEW: IPFS content address
        "doc_type": doc_type,
        "issued_at": issued_at
    }
    note_bytes = ("skillchain:j" + json.dumps(note_data)).encode()
    assert len(note_bytes) <= 1024, f"Note too long: {len(note_bytes)} bytes"

    params = client.suggested_params()
    txn = transaction.PaymentTxn(
        sender=address, sp=params, receiver=address,
        amt=0, note=note_bytes
    )
    signed_txn = txn.sign(private_key)
    tx_id = client.send_transaction(signed_txn)
    transaction.wait_for_confirmation(client, tx_id, 4)

    save_to_db(cert_hash, tx_id, doc_type, issued_at, ipfs_cid)  # store CID too
    return {"tx_id": tx_id, "ipfs_cid": ipfs_cid}

# Updated verify_hash — SQLite optional, IPFS path always works
from ipfs_service import fetch_certificate_metadata

def verify_hash(cert_hash: str) -> dict:
    tx_id = lookup_hash(cert_hash)

    if tx_id:
        client = get_indexer_client()
        response = client.transaction(tx_id)
        txn = response.get("transaction", {})

        note_raw = txn.get("note", "")
        note_decoded = base64.b64decode(note_raw).decode()
        data = json.loads(note_decoded.replace("skillchain:j", ""))

        if data.get("hash") != cert_hash:
            return {"valid": False, "reason": "Hash mismatch"}

        ipfs_cid = data.get("cid")
        issuer_info = {}

        if ipfs_cid:
            try:
                meta = fetch_certificate_metadata(ipfs_cid)

                issuer_info = {
                    "issued_by": meta.get("issued_by"),
                    "issuer_did": meta.get("issuer_did"),
                    "ipfs_cid": ipfs_cid,
                    "ipfs_url": f"https://gateway.pinata.cloud/ipfs/{ipfs_cid}"
                }

                # ✅ FIX: keep this INSIDE function
                from did_service import verify_provenance

                signature = meta.get("signature", "")
                _, issuer_address = load_wallet()

                if signature:
                    provenance = verify_provenance(
                        issuer_address, cert_hash, signature
                    )
                    issuer_info["signature_valid"] = provenance["verified"]
                    issuer_info["signature_institution"] = provenance.get("institution")
                else:
                    issuer_info["signature_valid"] = False
                    issuer_info["signature_warning"] = "No signature in metadata — legacy certificate"

            except Exception:
                pass

        return {
            "valid": True,
            "signature_valid": issuer_info.get("signature_valid", False),
            "tx_id": txn.get("id"),
            "confirmed_round": txn.get("confirmed-round"),
            "issued_by": issuer_info.get("issued_by"),
            "issuer_did": issuer_info.get("issuer_did"),
            "ipfs_cid": ipfs_cid,
        }

    # fallback
    return _verify_via_indexer(cert_hash)


def _verify_via_indexer(cert_hash: str) -> dict:
    """Searches Algorand indexer for the cert_hash. Works even if DB is wiped."""
    client = get_indexer_client()
    _, address = load_wallet()
    try:
        txns = client.search_transactions(
            address=address,
            note_prefix="skillchain:j".encode()
        ).get("transactions", [])

        for txn in txns:
            note_raw = txn.get("note", "")
            try:
                note_decoded = base64.b64decode(note_raw).decode()
                data = json.loads(note_decoded.replace("skillchain:j", ""))
                if data.get("hash") == cert_hash:
                    return {
                        "valid": True,
                        "tx_id": txn["id"],
                        "confirmed_round": txn["confirmed-round"],
                        "doc_type": data.get("doc_type"),
                        "issued_at": data.get("issued_at"),
                        "source": "algorand_indexer",
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
    _, address = load_wallet()
    print(f"Wallet ready: {address}")
    print("DB initialised.")