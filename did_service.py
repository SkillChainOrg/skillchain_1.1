from algosdk import account, mnemonic as mn, transaction
from algosdk.v2client import algod, indexer
from algosdk import encoding
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
from dotenv import load_dotenv
from email.mime.text import MIMEText
import secrets,smtplib
import os, json, base64, time, sqlite3
import hashlib

def generate_api_key() -> str:
    return secrets.token_hex(32)


load_dotenv()

ALGOD_URL     = os.getenv("ALGOD_URL", "https://testnet-api.algonode.cloud")
INDEXER_URL   = os.getenv("INDEXER_URL", "https://testnet-idx.algonode.cloud")
ALGOD_TOKEN   = ""
INDEXER_TOKEN = ""
DB_PATH       = "skillchain.db"

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

import secrets, smtplib
from email.mime.text import MIMEText

def init_did_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS did_registry (
            address       TEXT PRIMARY KEY,
            did           TEXT NOT NULL,
            institution   TEXT NOT NULL,
            public_key    TEXT NOT NULL,
            tx_id         TEXT NOT NULL,
            api_key       TEXT NOT NULL,
            domain        TEXT,
            registered_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pending_registrations (
            id            TEXT PRIMARY KEY,
            institution   TEXT NOT NULL,
            email         TEXT NOT NULL,
            domain        TEXT NOT NULL,
            verify_token  TEXT NOT NULL,
            verified      INTEGER DEFAULT 0,
            approved      INTEGER DEFAULT 0,
            created_at    TEXT
        )
    """)
    conn.commit()
    conn.close()

def request_registration(institution_name: str, email: str, domain: str) -> dict:
    registration_id = secrets.token_hex(8)
    verify_token = secrets.token_hex(16)

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO pending_registrations VALUES (?, ?, ?, ?, ?, 0, 0, ?)",
        (registration_id, institution_name, email, domain, verify_token, time.strftime("%Y-%m-%d"))
    )
    conn.commit()
    conn.close()

    verify_url = f"http://127.0.0.1:5000/verify-email?token={verify_token}"

    return {
        "registration_id": registration_id,
        "message": f"Verification email would be sent to {email}",
        "verify_url": verify_url,
        "status": "pending_email_verification"
    }

def verify_email_token(token: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, institution, email, domain FROM pending_registrations WHERE verify_token = ? AND verified = 0",
        (token,)
    ).fetchone()

    if not row:
        conn.close()
        return {"success": False, "reason": "Invalid or already used token"}

    conn.execute(
        "UPDATE pending_registrations SET verified = 1 WHERE verify_token = ?",
        (token,)
    )
    conn.commit()
    conn.close()

    return {
        "success": True,
        "registration_id": row[0],
        "institution": row[1],
        "message": "Email verified. Awaiting admin approval."
    }

def get_pending_registrations() -> list:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, institution, email, domain, created_at FROM pending_registrations WHERE verified = 1 AND approved = 0"
    ).fetchall()
    conn.close()
    return [{"id": r[0], "institution": r[1], "email": r[2], "domain": r[3], "created_at": r[4]} for r in rows]

def approve_registration(registration_id: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT institution, email, domain FROM pending_registrations WHERE id = ? AND verified = 1 AND approved = 0",
        (registration_id,)
    ).fetchone()

    if not row:
        conn.close()
        return {"success": False, "reason": "Registration not found or not verified"}

    conn.execute(
        "UPDATE pending_registrations SET approved = 1 WHERE id = ?",
        (registration_id,)
    )
    conn.commit()
    conn.close()

    result = register_did(row[0], row[2])
    return {"success": True, **result}

def validate_api_key(api_key: str) -> dict | None:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT address, did, institution, domain FROM did_registry WHERE api_key = ?",
        (api_key,)
    ).fetchone()
    conn.close()
    if row:
        return {"address": row[0], "did": row[1], "institution": row[2], "domain": row[3]}
    return None

def register_did(institution_name: str, domain: str = "") -> dict:
    private_key, address = load_wallet()
    
    # Create a deterministic institution-specific suffix
    # This makes each DID unique without needing separate wallets
    inst_suffix = hashlib.sha256(
        institution_name.strip().lower().encode()
    ).hexdigest()[:16]
    
    did = f"did:algo:testnet:{address}:{inst_suffix}"
    
def validate_api_key(api_key: str) -> dict | None:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT address, did, institution FROM did_registry WHERE api_key = ?",
        (api_key,)
    ).fetchone()
    conn.close()
    if row:
        return {"address": row[0], "did": row[1], "institution": row[2]}
    return None

def sign_credential(cert_hash: str) -> str:
    private_key, _ = load_wallet()
    private_key_bytes = base64.b64decode(private_key)[:32]
    signing_key = SigningKey(private_key_bytes, encoder=RawEncoder)
    signed = signing_key.sign(cert_hash.encode(), encoder=RawEncoder)
    signature = base64.b64encode(signed.signature).decode()
    return signature

def get_did_for_address(address: str) -> dict | None:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT did, institution, public_key FROM did_registry WHERE address = ?",
        (address,)
    ).fetchone()
    conn.close()
    if row:
        return {"did": row[0], "institution": row[1], "public_key": row[2]}
    return None

def verify_provenance(address: str, cert_hash: str, signature: str) -> dict:
    did_info = get_did_for_address(address)

    if not did_info:
        return {
            "verified": False,
            "reason": "Issuer address not in DID registry"
        }

    try:
        private_key, wallet_address = load_wallet()
        if wallet_address != address:
            return {
                "verified": False,
                "reason": "Transaction not signed by registered institution"
            }

        private_key_bytes = base64.b64decode(private_key)[:32]
        signing_key = SigningKey(private_key_bytes, encoder=RawEncoder)
        verify_key = signing_key.verify_key
        sig_bytes = base64.b64decode(signature)
        verify_key.verify(cert_hash.encode(), sig_bytes, encoder=RawEncoder)

        return {
            "verified": True,
            "institution": did_info["institution"],
            "did": did_info["did"]
        }

    except Exception:
        return {
            "verified": False,
            "reason": "Signature verification failed"
        }

if __name__ == "__main__":
    init_did_db()
    print("Testing DID registration...")
    result = register_did("Cummins College of Engineering")
    print(json.dumps(result, indent=2))

    print("\nTesting credential signing...")
    test_hash = "167d339f9fa3c31a71e05a72b896826da3e548f04eab9288fe388467ec4f6af9"
    signature = sign_credential(test_hash)
    print(f"Signature: {signature[:40]}...")

    print("\nTesting provenance verification...")
    _, address = load_wallet()
    provenance = verify_provenance(address, test_hash, signature)
    print(json.dumps(provenance, indent=2))