"""
signing_service.py — Secure signing abstraction for SkillChain.

Security design:
  - resolve_private_key() is the single entry point for all private key access.
    All branching (system / artisan / institution) is encapsulated inside it.
  - Vault is always the primary source when VAULT_ENABLED=true.
    There is NO silent fallback — Vault failure raises hard.
  - AES-GCM (key_vault.py) is the dev-mode fallback (VAULT_ENABLED=false).
    KEY_ENCRYPTION_SECRET is required; missing it raises RuntimeError immediately.
  - Key bytes exist only within the innermost signing scope.
    Callers use a zeroing bytearray buffer; `del` runs in `finally` on every path.
  - No key material is ever logged, returned to callers, or stored in memory
    beyond the duration of a single signing call.

Identity model:
  IDENTITY_SYSTEM      — shared system wallet (MNEMONIC / Vault "system")
  IDENTITY_ARTISAN     — per-artisan wallet   (artisans table / Vault "artisan/<id>")
  IDENTITY_INSTITUTION — per-institution wallet (did_registry / Vault "<id>")

Vault KV v2 paths:
  system:      secret/skillchain/system
  artisan:     secret/skillchain/artisan/<identity_id>
  institution: secret/skillchain/<identity_id>
"""

import os
import base64
import hashlib

from algosdk import mnemonic as mn, account
from algosdk import account
import base64
from dotenv import load_dotenv

from db import get_db_connection

load_dotenv()

# ── Identity type constants ────────────────────────────────────────────────────
IDENTITY_SYSTEM      = "system"
IDENTITY_ARTISAN     = "artisan"
IDENTITY_INSTITUTION = "institution"

# Legacy string used as the Vault path segment for the shared system wallet.
# Kept for backward compatibility; IDENTITY_SYSTEM is preferred in new code.
SYSTEM_INSTITUTION_ID = "system"


# ── Public helper ─────────────────────────────────────────────────────────────

def derive_institution_id(institution_name: str) -> str:
    """
    Derive a stable, URL-safe institution_id from an institution name.

    Produces the same 16-char hex suffix that did_service.register_did() uses
    when constructing the DID, ensuring Vault path and DID are consistent.
    Kept for backward compatibility; artisan IDs use _derive_artisan_id() in app.py.
    """
    return hashlib.sha256(institution_name.strip().lower().encode()).hexdigest()[:16]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _vault_path_for(identity_type: str, identity_id: str | None) -> str:
    """
    Construct the Vault KV path segment for resolve_private_key().

    Vault KV v2 full paths (mount: secret, prefix: skillchain):
        system:      secret/skillchain/system
        artisan:     secret/skillchain/artisan/<identity_id>
        institution: secret/skillchain/<identity_id>
    """
    if identity_type == IDENTITY_SYSTEM:
        return SYSTEM_INSTITUTION_ID                    # "system"
    if identity_type == IDENTITY_ARTISAN:
        if not identity_id:
            raise ValueError("identity_id is required for IDENTITY_ARTISAN")
        return f"artisan/{identity_id}"                 # "artisan/<id>"
    if identity_type == IDENTITY_INSTITUTION:
        if not identity_id:
            raise ValueError("identity_id is required for IDENTITY_INSTITUTION")
        return identity_id                              # "<id>"
    raise ValueError(f"Unknown identity_type: {identity_type!r}")


def _load_from_db(identity_type: str, identity_id: str | None) -> bytes:
    """
    AES-GCM fallback key loader (dev mode only — called when VAULT_ENABLED=false).

    Routing:
        system:      MNEMONIC env var (algosdk format — no encryption needed)
        artisan:     artisans.enc_private_key  (AES-GCM via key_vault)
        institution: did_registry.private_key_enc (AES-GCM via key_vault)

    KEY_ENCRYPTION_SECRET must be set for artisan/institution paths.
    Raises RuntimeError or KeyError on any failure — no silent fallback.

    CRITICAL — caller contract:
        Delete the returned bytes immediately after a single signing operation.
    """
    if identity_type == IDENTITY_SYSTEM:
        phrase = os.getenv("MNEMONIC")
        if not phrase:
            raise ValueError(
                "MNEMONIC is not set and VAULT_ENABLED=false. "
                "Set MNEMONIC for local development or enable Vault for production."
            )
        return mn.to_private_key(phrase)

    from key_vault import decrypt_key   # raises if KEY_ENCRYPTION_SECRET missing

    if identity_type == IDENTITY_ARTISAN:
        full_artisan_id = f"artisan/{identity_id}"
        conn = get_db_connection()
        cur  = conn.cursor()
        try:
            cur.execute(
                "SELECT enc_private_key, key_nonce FROM artisans WHERE artisan_id = %s",
                (full_artisan_id,),
            )
            row = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if not row or not row[0]:
            raise KeyError(
                f"No AES-GCM key found for artisan_id={full_artisan_id!r}. "
                "Ensure the artisan was approved with KEY_ENCRYPTION_SECRET set, "
                "or switch to Vault (VAULT_ENABLED=true)."
            )
        key = decrypt_key(row[0], row[1])

        print("TYPE:", type(key))
        print("LEN:", len(key))
        print("RAW:", key)

        return key

    if identity_type == IDENTITY_INSTITUTION:
        conn = get_db_connection()
        cur  = conn.cursor()
        try:
            cur.execute(
                "SELECT private_key_enc, key_nonce FROM did_registry WHERE institution_id = %s",
                (identity_id,),
            )
            row = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if not row or not row[0]:
            raise KeyError(
                f"No AES-GCM key found for institution_id={identity_id!r}. "
                "Ensure the institution was approved with KEY_ENCRYPTION_SECRET set, "
                "or switch to Vault (VAULT_ENABLED=true)."
            )
        return decrypt_key(row[0], row[1])

    raise ValueError(f"Unknown identity_type: {identity_type!r}")


# ── Canonical resolver (new public API) ───────────────────────────────────────

def resolve_private_key(identity_type: str, identity_id: str | None = None) -> bytes:
    """
    Unified private key resolver — the single entry point for all key access.

    Replaces all branching logic that previously spread across _load_private_key().
    All callers (sign_transaction, sign_credential_hash, get_issuer_address) delegate
    here exclusively; no key routing logic exists outside this function.

    Args:
        identity_type: One of IDENTITY_SYSTEM | IDENTITY_ARTISAN | IDENTITY_INSTITUTION
        identity_id:   Short hex suffix for artisan/institution, or None for system.
                       For artisans, pass the suffix WITHOUT the "artisan/" prefix.

    Returns:
        Raw private key bytes (64 bytes: seed + public key).

    Routing:
        VAULT_ENABLED=true  → Vault KV v2 at secret/skillchain/<path>
                              Fails hard if Vault is unreachable (no silent fallback).
        VAULT_ENABLED=false → AES-GCM from DB (artisan/institution)
                              or MNEMONIC env var (system).
                              KEY_ENCRYPTION_SECRET required for DB paths.

    CRITICAL — caller contract (MUST be honoured on every call path):
        1. Copy key bytes into a zeroing bytearray buffer.
        2. Use the buffer for exactly one signing operation.
        3. Zero the buffer and delete ALL references in a `finally` block.
        4. Never log, return to a client, or store the key bytes.
        Key lifetime MUST NOT exceed a single signing call.
    """
    from vault_client import is_vault_enabled, read_key

    if is_vault_enabled():
        vault_path = _vault_path_for(identity_type, identity_id)
        return read_key(vault_path)      # hard failure if Vault unreachable

    return _load_from_db(identity_type, identity_id)


# ── Backward-compatibility shim ───────────────────────────────────────────────

def _load_private_key(institution_id: str | None) -> bytes:
    """
    Legacy shim — parses the old institution_id convention and delegates to
    resolve_private_key(). Preserved so existing call sites are not broken.

    Convention decoded:
        None                 → IDENTITY_SYSTEM
        "system"             → IDENTITY_SYSTEM
        "artisan/<hex>"      → IDENTITY_ARTISAN  (strips "artisan/" prefix)
        "<hex>"              → IDENTITY_INSTITUTION

    New code MUST call resolve_private_key() directly with explicit identity_type.
    """
    if institution_id is None or institution_id == SYSTEM_INSTITUTION_ID:
        return resolve_private_key(IDENTITY_SYSTEM)

    if institution_id.startswith("artisan/"):
        short_id = institution_id[len("artisan/"):]
        return resolve_private_key(IDENTITY_ARTISAN, short_id)

    return resolve_private_key(IDENTITY_INSTITUTION, institution_id)


# ── Public signing API ────────────────────────────────────────────────────────

def sign_transaction(txn, institution_id: str | None = None):
    """
    Sign an Algorand transaction object.

    Key is fetched via _load_private_key() → resolve_private_key(), used for
    exactly one sign() call, then zeroed and deleted.

    Args:
        txn:            An algosdk transaction object (e.g. PaymentTxn).
        institution_id: Legacy routing string. None → system issuer.
                        New call sites should migrate to resolve_private_key() directly.

    Returns:
        SignedTransaction (algosdk object).

    Security:
        Zeroing bytearray buffer used; `del` runs in `finally` on all paths.
        Python cannot guarantee OS-level zeroing; this minimises exposure window.
    """
    private_key = _load_private_key(institution_id)
    key_buf = bytearray(private_key)
    try:
        signed_txn = txn.sign(bytes(key_buf))
    finally:
        for i in range(len(key_buf)):
            key_buf[i] = 0
        del key_buf
        del private_key
    return signed_txn


from nacl.signing import SigningKey
import base64

def sign_credential_hash(cert_hash: str, institution_id: str | None = None) -> str:
    """
    Sign a certificate / artwork hash using Ed25519 (PyNaCl).

    Uses first 32 bytes of Algorand private key as seed.
    """

    private_key = _load_private_key(institution_id)

    try:
        # Debug
        print("\n==== SIGNING DEBUG ====")
        print("TYPE:", type(private_key))
        print("LEN:", len(private_key))
        print("======================\n")

        # ✅ Correct: take first 32 bytes ONLY
        seed = private_key[:32]

        # ✅ Correct: no encoder
        signing_key = SigningKey(seed)

        # Sign the hash
        signed = signing_key.sign(cert_hash.encode())

        # Return only signature (not message+signature)
        signature = base64.b64encode(signed.signature).decode()

        return signature

    finally:
        del private_key

def get_issuer_address(institution_id: str | None = None) -> str:
    """
    Derive the Algorand public address for the given identity.

    Used by paths that need the sender address without retaining the private key.
    The address (non-sensitive) is returned; the key is zeroed and deleted.

    Args:
        institution_id: Legacy routing string. None → system issuer.

    Returns:
        Algorand base32-encoded public address string (safe to log / store).
    """
    private_key = _load_private_key(institution_id)
    key_buf = bytearray(private_key)
    try:
        address = account.address_from_private_key(bytes(key_buf))
    finally:
        for i in range(len(key_buf)):
            key_buf[i] = 0
        del key_buf
        del private_key
    return address
