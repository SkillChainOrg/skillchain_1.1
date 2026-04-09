"""
did_service.py — DID registry, institution registration, and credential signing for SkillChain.

Security design:
  - Private keys are NEVER loaded in this module.
  - signing_service is the sole authority for all private-key operations.
  - Per-institution keypairs are generated at approval time and stored in Vault
    (production) or AES-256-GCM encrypted in did_registry (dev mode).
"""

from algosdk.v2client import algod, indexer
from algosdk import encoding, transaction as algo_txn
from nacl.signing import VerifyKey
from nacl.encoding import RawEncoder
from dotenv import load_dotenv
from email.mime.text import MIMEText
import secrets, smtplib
import os, json, base64, time, sqlite3
import hashlib
import logging

load_dotenv()

log = logging.getLogger(__name__)

# Security: signing_service is the sole authority for private key access.
from signing_service import get_issuer_address, derive_institution_id, sign_transaction

ALGOD_URL     = os.getenv("ALGOD_URL",    "https://testnet-api.algonode.cloud")
INDEXER_URL   = os.getenv("INDEXER_URL",  "https://testnet-idx.algonode.cloud")
ALGOD_TOKEN   = ""
INDEXER_TOKEN = ""
DB_PATH       = os.getenv("DB_PATH", "skillchain.db")


def generate_api_key() -> str:
    return secrets.token_hex(32)


def get_algod_client():
    return algod.AlgodClient(ALGOD_TOKEN, ALGOD_URL)


def get_indexer_client():
    return indexer.IndexerClient(INDEXER_TOKEN, INDEXER_URL)


# ── DB initialisation ────────────────────────────────────────────────────────

def init_did_db():
    """Create base tables.  Schema migrations (ALTER TABLE) are in db_migrations.py."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS did_registry (
            address          TEXT PRIMARY KEY,
            did              TEXT NOT NULL,
            institution      TEXT NOT NULL,
            public_key       TEXT NOT NULL,
            tx_id            TEXT NOT NULL,
            api_key          TEXT NOT NULL,
            domain           TEXT,
            registered_at    TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pending_registrations (
            id           TEXT PRIMARY KEY,
            institution  TEXT NOT NULL,
            email        TEXT NOT NULL,
            domain       TEXT NOT NULL,
            verify_token TEXT NOT NULL,
            verified     INTEGER DEFAULT 0,
            approved     INTEGER DEFAULT 0,
            created_at   TEXT
        )
    """)
    conn.commit()
    conn.close()


# ── Registration flow ────────────────────────────────────────────────────────

def request_registration(institution_name: str, email: str, domain: str) -> dict:
    registration_id = secrets.token_hex(8)
    verify_token    = secrets.token_hex(16)

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO pending_registrations VALUES (?, ?, ?, ?, ?, 0, 0, ?)",
        (registration_id, institution_name, email, domain,
         verify_token, time.strftime("%Y-%m-%d"))
    )
    conn.commit()
    conn.close()

    verify_url = f"http://127.0.0.1:5000/verify-email?token={verify_token}"
    return {
        "registration_id": registration_id,
        "message":         f"Verification email would be sent to {email}",
        "verify_url":      verify_url,
        "status":          "pending_email_verification",
    }


def verify_email_token(token: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, institution, email, domain "
        "FROM pending_registrations WHERE verify_token = ? AND verified = 0",
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
        "success":         True,
        "registration_id": row[0],
        "institution":     row[1],
        "message":         "Email verified. Awaiting admin approval.",
    }


def get_pending_registrations() -> list:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, institution, email, domain, created_at "
        "FROM pending_registrations WHERE verified = 1 AND approved = 0"
    ).fetchall()
    conn.close()
    return [
        {"id": r[0], "institution": r[1], "email": r[2],
         "domain": r[3], "created_at": r[4]}
        for r in rows
    ]


def _get_pending_registration(registration_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    row = conn.execute("""
        SELECT * FROM pending_registrations
        WHERE id = ?
        AND verified = 1
        AND (approved IS NULL OR approved = 0)
    """, (registration_id,)).fetchone()

    conn.close()
    return dict(row) if row else None


# ── Institution funding ──────────────────────────────────────────────────────

def _fund_institution_address(institution_address: str,
                               amount_microalgos: int = 100_000) -> str:
    """
    Send microAlgos from the system wallet to a newly created institution wallet.

    This is the ONLY time the system wallet signs for an institution.
    After this funding call, all issuance is signed with the institution's own key.

    Args:
        institution_address: Algorand address of the newly created institution wallet.
        amount_microalgos:   Amount to send (default 0.1 ALGO — covers a few txn fees).

    Returns:
        Transaction ID of the funding transaction.
    """
    system_address = get_issuer_address()  # system wallet (public address only)
    client = get_algod_client()

    params = client.suggested_params()
    fund_txn = algo_txn.PaymentTxn(
        sender=system_address,
        sp=params,
        receiver=institution_address,
        amt=amount_microalgos,
        note=b"skillchain:institution-funding",
    )
    # institution_id=None → routes to system key in signing_service
    signed_txn = sign_transaction(fund_txn, institution_id=None)
    tx_id = client.send_transaction(signed_txn)
    algo_txn.wait_for_confirmation(client, tx_id, 4)
    log.info("Funded institution wallet %s — tx %s", institution_address, tx_id)
    return tx_id


# ── Approve registration — main key-generation entry point ───────────────────

def approve_registration(registration_id: str) -> dict:
    """
    Approve a verified institution registration.

    Sequence
    --------
    1. Look up the pending registration.
    2. Derive a stable institution_id from the institution name.
    3. Generate a fresh Algorand keypair for this institution.
    4. Store the private key in Vault (prod) or AES-GCM in did_registry (dev).
    5. Fund the new institution wallet from the system wallet.
    6. Register the DID and store the institution_address.
    7. Mark the pending registration as approved.
    """
    reg = _get_pending_registration(registration_id)
    

    if not reg:
        return {
            "success": False,
            "reason": "Registration not found, not verified, or already approved",
        }

    reg = dict(reg)

    institution_name = reg["institution"]
    domain           = reg["domain"]

    # ── Step 2: derive stable institution_id ─────────────────────────────────
    institution_id = derive_institution_id(institution_name)

    # ── Step 3: generate a fresh Algorand keypair ─────────────────────────────
    from algosdk import account as algo_account
    private_key, institution_address = algo_account.generate_account()

    # ── Step 4: store private key ─────────────────────────────────────────────
    private_key_enc = None
    key_nonce       = None

    try:
        from vault_client import is_vault_enabled
        if is_vault_enabled():
            from vault_client import store_key
            store_key(institution_id, private_key)
            # Key is now in Vault — wipe local copy immediately
        else:
            # Dev mode: AES-256-GCM in did_registry
            from key_vault import encrypt_key
            private_key_bytes = private_key.encode()
            private_key_enc, key_nonce = encrypt_key(private_key_bytes)
            del private_key_bytes
    finally:
        del private_key  # always wipe the plaintext key from this scope

    # ── Step 5: fund the new institution wallet ───────────────────────────────
    try:
        _fund_institution_address(institution_address, amount_microalgos=100_000)
    except Exception as exc:
        # Non-fatal: institution can be funded manually via TestNet faucet if needed
        log.warning(
            "Auto-funding failed for %s: %s — fund manually before first issuance.",
            institution_address, exc
        )

    # ── Step 6: register DID with institution's own address ───────────────────
    result = register_did(
        institution_name,
        domain,
        institution_address=institution_address,
        institution_id=institution_id,
        private_key_enc=private_key_enc,
        key_nonce=key_nonce,
    )

    # ── Step 7: mark approved ─────────────────────────────────────────────────
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE pending_registrations SET approved = 1 WHERE id = ?",
        (registration_id,)
    )
    conn.commit()
    conn.close()

    return {"success": True, **result}


# ── DID registration ─────────────────────────────────────────────────────────

def register_did(
    institution_name: str,
    domain: str = "",
    institution_address: str | None = None,
    institution_id: str | None = None,
    private_key_enc: str | None = None,
    key_nonce: str | None = None,
) -> dict:
    """
    Write a DID record for an institution into did_registry.

    If institution_address is not provided, falls back to the system wallet
    address and marks the row as wallet_version=1 (legacy).

    Args:
        institution_name:  Display name of the institution.
        domain:            Verified domain string.
        institution_address: The institution's own Algorand address (wallet_version=2).
        institution_id:    Stable hex ID derived from institution name.
        private_key_enc:   AES-GCM ciphertext (dev mode only; None if using Vault).
        key_nonce:         AES-GCM nonce (dev mode only; None if using Vault).

    Returns:
        dict with did, address, institution_id, api_key, domain, wallet_version.
    """
    # Determine whether this is a per-institution or legacy (system) registration
    if institution_address is None:
        institution_address = get_issuer_address()
        wallet_version = 1
        log.warning(
            "register_did called without institution_address — using legacy system wallet."
        )
    else:
        wallet_version = 2

    if institution_id is None:
        institution_id = derive_institution_id(institution_name)

    # DID uses the institution's own address as the identifier component
    inst_suffix = hashlib.sha256(
        institution_name.strip().lower().encode()
    ).hexdigest()[:16]
    did = f"did:algo:testnet:{institution_address}:{inst_suffix}"

    api_key = generate_api_key()

    # Public key is safely recoverable from the Algorand address (no private key needed)
    public_key_b64 = base64.b64encode(
        encoding.decode_address(institution_address)
    ).decode()

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT OR REPLACE INTO did_registry
            (address, did, institution, public_key, tx_id, api_key, domain,
             registered_at, institution_id, institution_address, wallet_version,
             private_key_enc, key_nonce)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            institution_address, did, institution_name, public_key_b64,
            "pending", api_key, domain, time.strftime("%Y-%m-%d"),
            institution_id, institution_address, wallet_version,
            private_key_enc, key_nonce,
        ),
    )
    conn.commit()
    conn.close()

    return {
        "did":            did,
        "address":        institution_address,
        "institution_id": institution_id,
        "api_key":        api_key,
        "domain":         domain,
        "wallet_version": wallet_version,
    }


# ── API key validation ────────────────────────────────────────────────────────

def validate_api_key(api_key: str) -> dict | None:
    """
    Validate an API key and return institution data including institution_id
    and wallet_version so callers can route signing correctly.

    Returns:
        dict with address, did, institution, domain, api_key, institution_id,
        wallet_version — or None if the key is invalid.

    institution_id is None for legacy rows (wallet_version=1).
    wallet_version defaults to 1 if the column is NULL (pre-migration rows).
    """
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        """
        SELECT address, did, institution, domain, api_key,
               institution_id, wallet_version
        FROM did_registry WHERE api_key = ?
        """,
        (api_key,),
    ).fetchone()
    conn.close()

    if not row:
        return None

    institution_id  = row[5]
    wallet_version  = row[6] if row[6] is not None else 1

    # Legacy rows have institution_id='LEGACY_SYSTEM' or NULL — normalise to None
    if institution_id in (None, "LEGACY_SYSTEM"):
        institution_id = None

    return {
        "address":        row[0],
        "did":            row[1],
        "institution":    row[2],
        "domain":         row[3],
        "api_key":        row[4],
        "institution_id": institution_id,
        "wallet_version": wallet_version,
    }


# ── Credential signing (thin wrapper — key stays in signing_service) ──────────

def sign_credential(cert_hash: str, institution_id: str | None = None) -> str:
    """
    Sign a certificate hash.

    Delegates entirely to signing_service so no private key bytes
    ever enter this function's scope.

    Args:
        cert_hash:      SHA-256 hex digest of the normalised certificate image.
        institution_id: Routes to per-institution key (or system if None).
    """
    from signing_service import sign_credential_hash
    return sign_credential_hash(cert_hash, institution_id=institution_id)


# ── DID lookup helpers ────────────────────────────────────────────────────────

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


# ── Provenance verification ───────────────────────────────────────────────────

def verify_provenance(address: str, cert_hash: str, signature: str) -> dict:
    did_info = get_did_for_address(address)

    if not did_info:
        return {"verified": False, "reason": "Issuer address not in DID registry"}

    try:
        # Security: the Ed25519 public key is recovered directly from the Algorand
        # address via encoding.decode_address() — no private key required.
        public_key_bytes = encoding.decode_address(address)   # 32 bytes, non-secret
        verify_key = VerifyKey(public_key_bytes, encoder=RawEncoder)
        sig_bytes   = base64.b64decode(signature)
        verify_key.verify(cert_hash.encode(), sig_bytes, encoder=RawEncoder)

        return {
            "verified":    True,
            "institution": did_info["institution"],
            "did":         did_info["did"],
        }
    except Exception:
        return {"verified": False, "reason": "Signature verification failed"}


# ── CLI test harness ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_did_db()
    print("Testing DID registration (legacy system wallet)...")
    result = register_did("Cummins College of Engineering")
    print(json.dumps(result, indent=2))

    print("\nTesting credential signing...")
    test_hash = "167d339f9fa3c31a71e05a72b896826da3e548f04eab9288fe388467ec4f6af9"
    signature = sign_credential(test_hash)
    print(f"Signature: {signature[:40]}...")

    print("\nTesting provenance verification...")
    address    = get_issuer_address()
    provenance = verify_provenance(address, test_hash, signature)
    print(json.dumps(provenance, indent=2))
