"""
signing_service.py — Secure signing abstraction for SkillChain.

Security design:
  - Private keys are fetched from Vault immediately before signing and deleted after.
  - When VAULT_ENABLED=true the system fails hard if Vault is unreachable.
    There is NO silent fallback to MNEMONIC — issuer isolation must be maintained.
  - When VAULT_ENABLED=false (dev mode only), MNEMONIC env var is used.
  - Key bytes exist only within the innermost function scope; `del` is called
    in a `finally` block to minimise the in-memory exposure window.
  - No key material is logged, returned, or stored beyond the signing call.
"""

import os
import base64
import hashlib

from algosdk import mnemonic as mn, account
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
from dotenv import load_dotenv

from db import get_db_connection

load_dotenv()

# Vault path segment used for the system-level (shared) issuer wallet
SYSTEM_INSTITUTION_ID = "system"


# ---------------------------------------------------------------------------
# Public helper
# ---------------------------------------------------------------------------

def derive_institution_id(institution_name: str) -> str:
    """
    Derive a stable, URL-safe institution_id from an institution name.

    Produces the same 16-char hex suffix that did_service.register_did() uses
    when constructing the DID, ensuring Vault path and DID are consistent.

    Example:
        "Cummins College" → "8f3a1c9d24b07e5f"
    """
    return hashlib.sha256(institution_name.strip().lower().encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Internal key loader
# ---------------------------------------------------------------------------

def _load_private_key(institution_id: str | None) -> str:
    """
    Fetch the private key (base64 string) for the given institution.

    Routing logic:
      - VAULT_ENABLED=true  → always fetch from Vault; fail hard if unavailable.
      - VAULT_ENABLED=false → load from MNEMONIC env var (dev/local mode only).

    Args:
        institution_id: Vault path segment. None resolves to SYSTEM_INSTITUTION_ID.

    Returns:
        Base64-encoded private key string (algosdk format).

    CRITICAL — caller contract:
        The returned string MUST be deleted from the caller's local scope
        immediately after use. Never log it, return it, or store it.
    """
    from vault_client import is_vault_enabled, fetch_key

    if is_vault_enabled():
        resolved_id = institution_id or SYSTEM_INSTITUTION_ID
        # Vault is required — no fallback, no exception swallowing
        return fetch_key(resolved_id)

    # ── Dev mode (VAULT_ENABLED=false) ─────────────────────────────────────────
    resolved_id = institution_id or SYSTEM_INSTITUTION_ID

    if resolved_id == SYSTEM_INSTITUTION_ID or institution_id is None:
        # System wallet: load from MNEMONIC env var
        phrase = os.getenv("MNEMONIC")
        if not phrase:
            raise ValueError(
                "MNEMONIC is not set and VAULT_ENABLED=false. "
                "Set MNEMONIC for local development or enable Vault for production."
            )
        return mn.to_private_key(phrase)

    # Per-institution dev mode: fetch AES-GCM encrypted key from did_registry
    from db import get_db_connection
    from key_vault import decrypt_key

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT private_key_enc, key_nonce FROM did_registry WHERE institution_id = %s",
        (institution_id,),
)
    row = cur.fetchone()

    cur.close()
    conn.close()

    if not row or not row[0]:
        raise KeyError(
            f"No dev-mode key found for institution_id={institution_id!r}. "
            "Ensure the institution was approved after KEY_ENCRYPTION_KEY was set."
        )

    private_key_bytes = decrypt_key(row[0], row[1])
    # algosdk expects a base64-encoded 64-byte private key string
    try:
        return base64.b64encode(private_key_bytes).decode()
    finally:
        del private_key_bytes  # wipe bytes before returning the base64 string


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def sign_transaction(txn, institution_id: str | None = None):
    """
    Sign an Algorand transaction object securely.

    The private key is fetched, used to sign, and deleted from local scope
    in a single tightly-scoped call — the key is never returned or stored.

    Args:
        txn:            An algosdk transaction object (e.g. PaymentTxn).
        institution_id: Vault institution_id. None → system issuer.

    Returns:
        SignedTransaction (algosdk object).

    Security:
        - `del private_key` runs in `finally` so the key is cleared even on error.
        - Python does not guarantee memory zeroing; this minimises exposure window.
    """
    private_key = _load_private_key(institution_id)
    try:
        signed_txn = txn.sign(private_key)  # key used exactly once
    finally:
        del private_key  # wipe from this scope immediately after signing
    return signed_txn


def sign_credential_hash(cert_hash: str, institution_id: str | None = None) -> str:
    """
    Sign a certificate hash using NaCl Ed25519.

    Replaces did_service.sign_credential() with a secure fetch-sign-delete pattern.
    The private key and all derived sensitive intermediaries are deleted before return.

    Args:
        cert_hash:      SHA-256 hex digest of the normalised certificate image.
        institution_id: Vault institution_id. None → system issuer.

    Returns:
        Base64-encoded Ed25519 signature string.

    Security:
        - private_key, private_key_bytes, and signing_key are all local to this scope.
        - `del` is called on private_key in `finally`; others are GC-eligible after return.
    """
    private_key = _load_private_key(institution_id)
    try:
        # Derive Ed25519 signing key from the first 32 bytes of the algosdk private key
        private_key_bytes = base64.b64decode(private_key)[:32]
        signing_key = SigningKey(private_key_bytes, encoder=RawEncoder)
        signed = signing_key.sign(cert_hash.encode(), encoder=RawEncoder)
        signature = base64.b64encode(signed.signature).decode()
    finally:
        del private_key  # most critical: wipe the raw key bytes first
    return signature


def get_issuer_address(institution_id: str | None = None) -> str:
    """
    Derive the Algorand public address for the given institution.

    Used by verification and transaction-building paths that need the sender
    address but must not retain the private key.

    Args:
        institution_id: Vault institution_id. None → system issuer.

    Returns:
        Algorand base32-encoded public address string (safe to log/store).

    Security:
        Private key is fetched and deleted before this function returns.
        Only the public address (non-sensitive) is returned.
    """
    private_key = _load_private_key(institution_id)
    try:
        address = account.address_from_private_key(private_key)
    finally:
        del private_key  # address is public; key is not needed beyond this line
    return address
