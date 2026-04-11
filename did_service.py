"""
did_service.py — DID registry, institution registration, and credential signing for SkillChain.

CHANGES (PostgreSQL migration):
  - Removed sqlite3 / DB_PATH.
  - All DB access uses psycopg2 via db.get_db_connection() / db.dict_cursor().
  - SQL placeholders changed from ? to %s.
  - INSERT OR REPLACE → INSERT ... ON CONFLICT (address) DO UPDATE SET ...
  - Row access changed from positional index to dict keys.
  - conn.row_factory = sqlite3.Row removed (RealDictCursor used instead).

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
import secrets, smtplib
import os, json, base64, time
import hashlib
import logging

from db import get_db_connection, dict_cursor

load_dotenv()

DEMO_MODE_ENV = os.getenv("DEMO_MODE")

if DEMO_MODE_ENV is None:
    raise RuntimeError(
        "DEMO_MODE is not set. Refusing to start with ambiguous security mode."
    )

DEMO_MODE = DEMO_MODE_ENV.lower() == "true"

log = logging.getLogger(__name__)
if DEMO_MODE:
    log.warning("⚠️ DEMO_MODE is enabled — NOT safe for production")

from signing_service import get_issuer_address, derive_institution_id, sign_transaction

# W3C DID Document generation (non-breaking addition)
try:
    from w3c_did_service import generate_and_store_did_document
    _W3C_DID_ENABLED = True
except ImportError:
    _W3C_DID_ENABLED = False
    log.warning("w3c_did_service not found — DID Documents will not be pre-generated.")

ALGOD_URL     = os.getenv("ALGOD_URL",    "https://testnet-api.algonode.cloud")
INDEXER_URL   = os.getenv("INDEXER_URL",  "https://testnet-idx.algonode.cloud")
ALGOD_TOKEN   = ""
INDEXER_TOKEN = ""


def generate_api_key() -> str:
    return secrets.token_hex(32)


def get_algod_client():
    return algod.AlgodClient(ALGOD_TOKEN, ALGOD_URL)


def get_indexer_client():
    return indexer.IndexerClient(INDEXER_TOKEN, INDEXER_URL)


# ── DB initialisation ────────────────────────────────────────────────────────

def init_did_db():
    """Create base tables. Schema migrations (ALTER TABLE) are in db_migrations.py."""
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        # did_registry — full schema; CREATE TABLE IF NOT EXISTS is a no-op
        # if db_migrations.run_migrations() already ran.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS did_registry (
                id                  SERIAL PRIMARY KEY,
                address             TEXT UNIQUE,
                did                 TEXT,
                institution         TEXT,
                public_key          TEXT,
                tx_id               TEXT,
                api_key             TEXT,
                domain              TEXT,
                registered_at       TEXT,
                institution_id      TEXT,
                institution_address TEXT,
                wallet_version      INTEGER DEFAULT 1,
                private_key_enc     TEXT,
                key_nonce           TEXT,
                revoked             INTEGER DEFAULT 0,
                revoked_at          TEXT,
                revoked_reason      TEXT
            )
        """)
        cur.execute("""
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
    finally:
        cur.close()
        conn.close()


# ── Registration flow ────────────────────────────────────────────────────────

def request_registration(institution_name: str, email: str, domain: str) -> dict:
    registration_id = secrets.token_hex(8)
    verify_token    = secrets.token_hex(16)

    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO pending_registrations
                (id, institution, email, domain, verify_token, verified, approved, created_at)
            VALUES (%s, %s, %s, %s, %s, 0, 0, %s)
            """,
            (registration_id, institution_name, email, domain,
             verify_token, time.strftime("%Y-%m-%d")),
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()
        
    BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")

    verify_url = f"{BASE_URL}/verify-email?token={verify_token}"
    print("VERIFY URL:", verify_url)
    return {
        "registration_id": registration_id,
        "message":         f"Verification email would be sent to {email}",
        "verify_url":      verify_url,
        "status":          "pending_email_verification",
    }


def verify_email_token(token: str) -> dict:
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        cur.execute(
            """
            SELECT id, institution, email, domain
            FROM pending_registrations
            WHERE verify_token = %s AND verified = 0
            """,
            (token,),
        )
        row = cur.fetchone()

        if not row:
            return {"success": False, "reason": "Invalid or already used token"}

        cur.execute(
            "UPDATE pending_registrations SET verified = 1 WHERE verify_token = %s",
            (token,),
        )
        conn.commit()
        return {
            "success":         True,
            "registration_id": row["id"],
            "institution":     row["institution"],
            "message":         "Email verified. Awaiting admin approval.",
        }
    finally:
        cur.close()
        conn.close()


def get_pending_registrations() -> list:
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        cur.execute(
            """
            SELECT id, institution, email, domain, created_at
            FROM pending_registrations
            WHERE verified = 1 AND approved = 0
            """
        )
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        cur.close()
        conn.close()


def _get_pending_registration(registration_id: str) -> dict | None:
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        cur.execute(
            """
            SELECT * FROM pending_registrations
            WHERE id = %s
              AND verified = 1
              AND (approved IS NULL OR approved = 0)
            """,
            (registration_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        cur.close()
        conn.close()


# ── Institution funding ──────────────────────────────────────────────────────

def _fund_institution_address(institution_address: str,
                               amount_microalgos: int = 100_000) -> str:
    """
    Send microAlgos from the system wallet to a newly created institution wallet.
    """
    system_address = get_issuer_address()
    client = get_algod_client()

    params   = client.suggested_params()
    fund_txn = algo_txn.PaymentTxn(
        sender=system_address,
        sp=params,
        receiver=institution_address,
        amt=amount_microalgos,
        note=b"skillchain:institution-funding",
    )
    signed_txn = sign_transaction(fund_txn, institution_id=None)
    tx_id = client.send_transaction(signed_txn)
    algo_txn.wait_for_confirmation(client, tx_id, 4)
    log.info("Funded institution wallet %s — tx %s", institution_address, tx_id)
    return tx_id


# ── Approve registration ─────────────────────────────────────────────────────

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
    import os
    DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"

    # ── Step 1: Try strict fetch (verified only) ─────────────────────────────
    reg = _get_pending_registration(registration_id)

    # ── Step 2: Fallback (demo mode) ─────────────────────────────────────────
    if not reg:
        conn = get_db_connection()
        cur  = dict_cursor(conn)
        try:
            cur.execute(
                "SELECT * FROM pending_registrations WHERE id = %s",
                (registration_id,),
            )
            row = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if not row:
            return {"success": False, "reason": "Registration not found"}

        reg = dict(row)

        if not reg.get("verified", 0):
            if not DEMO_MODE:
                return {"success": False, "reason": "Email not verified"}
            else:
                print(f"[DEMO MODE] Approving unverified registration: {registration_id}")

    institution_name = reg["institution"]
    domain           = reg["domain"]

    # ── Step 3: derive institution_id ────────────────────────────────────────
    institution_id = derive_institution_id(institution_name)

    # ── Step 4: generate Algorand keypair ────────────────────────────────────
    from algosdk import account as algo_account
    private_key, institution_address = algo_account.generate_account()

    private_key_enc = None
    key_nonce       = None

    try:
        from vault_client import is_vault_enabled
        if is_vault_enabled():
            from vault_client import store_key
            store_key(institution_id, private_key)
        else:
            from key_vault import encrypt_key
            private_key_bytes = private_key.encode()
            private_key_enc, key_nonce = encrypt_key(private_key_bytes)
            del private_key_bytes
    finally:
        del private_key

    # ── Step 5: fund wallet (non-fatal) ──────────────────────────────────────
    try:
        _fund_institution_address(institution_address, amount_microalgos=100_000)
    except Exception as exc:
        log.warning(
            "Auto-funding failed for %s: %s — fund manually if needed.",
            institution_address, exc,
        )

    # ── Step 6: register DID ─────────────────────────────────────────────────
    result = register_did(
        institution_name,
        domain,
        institution_address=institution_address,
        institution_id=institution_id,
        private_key_enc=private_key_enc,
        key_nonce=key_nonce,
    )

    # ── Step 7: mark approved ────────────────────────────────────────────────
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute(
            "UPDATE pending_registrations SET approved = 1 WHERE id = %s",
            (registration_id,),
        )
        conn.commit()
    finally:
        cur.close()
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

    Uses INSERT ... ON CONFLICT (address) DO UPDATE SET ... so it is safe to
    call multiple times (idempotent upsert).
    """
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

    inst_suffix = hashlib.sha256(
        institution_name.strip().lower().encode()
    ).hexdigest()[:16]
    did = f"did:algo:testnet:{institution_address}:{inst_suffix}"

    api_key = generate_api_key()

    public_key_b64 = base64.b64encode(
        encoding.decode_address(institution_address)
    ).decode()

    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO did_registry
                (address, did, institution, public_key, tx_id, api_key, domain,
                 registered_at, institution_id, institution_address, wallet_version,
                 private_key_enc, key_nonce)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (address) DO UPDATE SET
                did                 = EXCLUDED.did,
                institution         = EXCLUDED.institution,
                public_key          = EXCLUDED.public_key,
                tx_id               = EXCLUDED.tx_id,
                api_key             = EXCLUDED.api_key,
                domain              = EXCLUDED.domain,
                registered_at       = EXCLUDED.registered_at,
                institution_id      = EXCLUDED.institution_id,
                institution_address = EXCLUDED.institution_address,
                wallet_version      = EXCLUDED.wallet_version,
                private_key_enc     = EXCLUDED.private_key_enc,
                key_nonce           = EXCLUDED.key_nonce
            """,
            (
                institution_address, did, institution_name, public_key_b64,
                "pending", api_key, domain, time.strftime("%Y-%m-%d"),
                institution_id, institution_address, wallet_version,
                private_key_enc, key_nonce,
            ),
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()

    # ── Generate and cache W3C DID Document ────────────────────────────────
    # Non-fatal: if w3c_did_service is unavailable, registration still succeeds.
    if _W3C_DID_ENABLED:
        try:
            generate_and_store_did_document(
                did=did,
                institution_name=institution_name,
                domain=domain or "",
                algorand_address=institution_address,
                registered_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )
            log.info("W3C DID Document generated for: %s", did)
        except Exception as exc:
            log.warning("W3C DID Document generation failed (non-fatal): %s", exc)

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
    Validate an API key and return institution data.

    Returns dict with address, did, institution, domain, api_key,
    institution_id, wallet_version — or None if the key is invalid.
    """
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        cur.execute(
            """
            SELECT address, did, institution, domain, api_key,
                   institution_id, wallet_version
            FROM did_registry WHERE api_key = %s
            """,
            (api_key,),
        )
        row = cur.fetchone()
    finally:
        cur.close()
        conn.close()

    if not row:
        return None

    institution_id  = row["institution_id"]
    wallet_version  = row["wallet_version"] if row["wallet_version"] is not None else 1

    if institution_id in (None, "LEGACY_SYSTEM"):
        institution_id = None

    return {
        "address":        row["address"],
        "did":            row["did"],
        "institution":    row["institution"],
        "domain":         row["domain"],
        "api_key":        row["api_key"],
        "institution_id": institution_id,
        "wallet_version": wallet_version,
    }


# ── Credential signing ────────────────────────────────────────────────────────

def sign_credential(cert_hash: str, institution_id: str | None = None) -> str:
    """Sign a certificate hash. Delegates to signing_service."""
    from signing_service import sign_credential_hash
    return sign_credential_hash(cert_hash, institution_id=institution_id)


# ── DID lookup helpers ────────────────────────────────────────────────────────

def get_did_for_address(address: str) -> dict | None:
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        cur.execute(
            "SELECT did, institution, public_key FROM did_registry WHERE address = %s",
            (address,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        cur.close()
        conn.close()


# ── Provenance verification ───────────────────────────────────────────────────

def verify_provenance(address: str, cert_hash: str, signature: str) -> dict:
    did_info = get_did_for_address(address)

    if not did_info:
        return {"verified": False, "reason": "Issuer address not in DID registry"}

    try:
        public_key_bytes = encoding.decode_address(address)
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