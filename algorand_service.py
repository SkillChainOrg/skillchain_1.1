from dotenv import load_dotenv
from algosdk import account, mnemonic as mn, transaction
from algosdk.v2client import algod, indexer
import os, json, base64, time
import sqlite3
from PIL import Image
import io
import hashlib

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

def save_to_db(cert_hash: str, tx_id: str, doc_type: str, issued_at: str):
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

def anchor_hash(cert_hash: str, doc_type: str = "academic", holder_name: str = "") -> str:
    private_key, address = load_wallet()
    client = get_algod_client()

    issued_at = time.strftime("%Y-%m-%d")
    
    name_hash = hashlib.sha256(
        holder_name.strip().lower().encode()
    ).hexdigest() if holder_name else ""
    
    note_data = {
        "hash": cert_hash,
        "doc_type": doc_type,
        "name_hash": name_hash,
        "issued_at": issued_at
    }
    note_bytes = ("skillchain:j" + json.dumps(note_data)).encode()

    params = client.suggested_params()
    txn = transaction.PaymentTxn(
        sender=address,
        sp=params,
        receiver=address,
        amt=0,
        note=note_bytes
    )

    signed_txn = txn.sign(private_key)
    tx_id = client.send_transaction(signed_txn)
    transaction.wait_for_confirmation(client, tx_id, 4)

    save_to_db(cert_hash, tx_id, doc_type, issued_at)
    return tx_id

def verify_hash(cert_hash: str) -> dict:
    tx_id = lookup_hash(cert_hash)
    
    if not tx_id:
        return {"valid": False, "reason": "Certificate not found"}

    client = get_indexer_client()
    response = client.transaction(tx_id)
    txn = response.get("transaction", {})

    note_raw = txn.get("note", "")
    note_decoded = base64.b64decode(note_raw).decode()
    note_json = note_decoded.replace("skillchain:j", "")
    data = json.loads(note_json)

    if data.get("hash") == cert_hash:
        return {
            "valid": True,
            "tx_id": txn["id"],
            "confirmed_round": txn["confirmed-round"],
            "doc_type": data.get("doc_type", "academic"),
            "issued_at": data.get("issued_at"),
            "explorer_url": f"https://testnet.explorer.perawallet.app/tx/{txn['id']}"
        }
    return {"valid": False, "reason": "Hash mismatch"}

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