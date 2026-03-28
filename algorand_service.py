from dotenv import load_dotenv
from algosdk import account, mnemonic as mn, transaction
from algosdk.v2client import algod, indexer
from ipfs_service import pin_certificate_metadata,fetch_certificate_metadata,pin_with_retry
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

def load_wallet():
    phrase = os.getenv("MNEMONIC")
    if not phrase:
        raise ValueError("MNEMONIC not set in .env")
    private_key = mn.to_private_key(phrase)
    address = account.address_from_private_key(private_key)
    return private_key, address

def anchor_hash(cert_hash: str, doc_type: str,
                institution: dict, signature: str) -> dict:
    private_key, address = load_wallet()
    client = get_algod_client()
    issued_at = time.strftime("%Y-%m-%d")

    # Build IPFS metadata — all the rich data lives here
    metadata = {
        "version": "1.0",
        "cert_hash": cert_hash,       # full hash in IPFS
        "doc_type": doc_type,
        "issued_by": institution["institution"],
        "issuer_did": institution["did"],
        "issued_at": issued_at,
        "signature": signature
    }

    # Retry-wrapped pin
    ipfs_cid = pin_with_retry(metadata)

    # Note contains ONLY the CID — nothing else needed
    note_data = {"sc": "1", "cid": ipfs_cid}
    note_bytes = json.dumps(note_data).encode()

    # This will always be ~35 bytes — can never overflow 1024
    assert len(note_bytes) < 100, f"Unexpected note size: {len(note_bytes)}"

    params = client.suggested_params()
    txn = transaction.PaymentTxn(
        sender=address, sp=params,
        receiver=address, amt=0, note=note_bytes
    )
    signed_txn = txn.sign(private_key)
    tx_id = client.send_transaction(signed_txn)
    transaction.wait_for_confirmation(client, tx_id, 4)

    save_to_db(cert_hash, tx_id, doc_type, issued_at, ipfs_cid)
    return {"tx_id": tx_id, "ipfs_cid": ipfs_cid}

def verify_hash(cert_hash: str) -> dict:
    tx_id = lookup_hash(cert_hash)

    if tx_id:
        client = get_indexer_client()
        txn = client.transaction(tx_id).get("transaction", {})
        note_raw = txn.get("note", "")
        note = json.loads(base64.b64decode(note_raw).decode())

        ipfs_cid = note.get("cid")
        if not ipfs_cid:
            return {"valid": False, "reason": "Malformed note — no CID"}

        # All verification now happens against IPFS data
        meta = fetch_certificate_metadata(ipfs_cid)  # gateway fallback chain

        if meta.get("cert_hash") != cert_hash:
            return {"valid": False, "reason": "IPFS hash mismatch — data tampered"}

        # Verify signature
        from did_service import verify_provenance
        _, issuer_address = load_wallet()
        provenance = verify_provenance(
            issuer_address,
            cert_hash,
            meta.get("signature", "")
        )

        return {
            "valid": True,
            "signature_valid": provenance["verified"],
            "tx_id": txn["id"],
            "confirmed_round": txn["confirmed-round"],
            "issued_by": meta.get("issued_by"),
            "issuer_did": meta.get("issuer_did"),
            "doc_type": meta.get("doc_type"),
            "issued_at": meta.get("issued_at"),
            "ipfs_cid": ipfs_cid,
            "ipfs_url": f"https://gateway.pinata.cloud/ipfs/{ipfs_cid}",
            "explorer_url": f"https://testnet.explorer.perawallet.app/tx/{txn['id']}"
        }

    return _verify_via_indexer(cert_hash)


def _verify_via_indexer(cert_hash: str) -> dict:
    client = get_indexer_client()
    _, address = load_wallet()
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
    _, address = load_wallet()
    print(f"Wallet ready: {address}")
    print("DB initialised.")