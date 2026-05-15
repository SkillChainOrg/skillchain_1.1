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
import logging

from algosdk import mnemonic as mn, account
from dotenv import load_dotenv
from nacl.signing import SigningKey

from db import get_db_connection

load_dotenv()
log = logging.getLogger(__name__)

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
        key = mn.to_private_key(phrase)
        _log_key_diagnostics("load_from_db.system.mnemonic", key)
        return key

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
        log.info(
            "AES key lookup | identity_type=artisan artisan_id=%s ciphertext_type=%s ciphertext_len=%s nonce_type=%s nonce_len=%s ciphertext_preview=%s nonce_preview=%s",
            full_artisan_id,
            type(row[0]).__name__,
            len(row[0]) if row[0] is not None and hasattr(row[0], "__len__") else "unknown",
            type(row[1]).__name__,
            len(row[1]) if row[1] is not None and hasattr(row[1], "__len__") else "unknown",
            _safe_hex_preview(row[0]),
            _safe_hex_preview(row[1]),
        )
        key = decrypt_key(row[0], row[1])
        _log_key_diagnostics("load_from_db.artisan.decrypted", key)
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
        log.info(
            "AES key lookup | identity_type=institution institution_id=%s ciphertext_type=%s ciphertext_len=%s nonce_type=%s nonce_len=%s ciphertext_preview=%s nonce_preview=%s",
            identity_id,
            type(row[0]).__name__,
            len(row[0]) if row[0] is not None and hasattr(row[0], "__len__") else "unknown",
            type(row[1]).__name__,
            len(row[1]) if row[1] is not None and hasattr(row[1], "__len__") else "unknown",
            _safe_hex_preview(row[0]),
            _safe_hex_preview(row[1]),
        )
        key = decrypt_key(row[0], row[1])
        _log_key_diagnostics("load_from_db.institution.decrypted", key)
        return key

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
        key = read_key(vault_path)      # hard failure if Vault unreachable
        _log_key_diagnostics(f"resolve_private_key.vault.{vault_path}", key)
        return key

    return _load_from_db(identity_type, identity_id)


def _looks_like_hex(text: str) -> bool:
    if len(text) % 2 != 0:
        return False
    try:
        bytes.fromhex(text)
        return True
    except ValueError:
        return False


def _safe_hex_preview(data: bytes | bytearray | str | None, limit: int = 8) -> str:
    if data is None:
        return "none"
    if isinstance(data, str):
        preview = data[: limit * 2]
        return preview if preview else "empty-str"
    raw = bytes(data[:limit])
    return raw.hex() if raw else "empty-bytes"


def _logged_b64decode(value: str, *, caller: str) -> bytes:
    log.info(
        "Base64 decode attempt | caller=%s type=%s len=%s preview=%s",
        caller,
        type(value).__name__,
        len(value) if hasattr(value, "__len__") else "unknown",
        _safe_hex_preview(value),
    )
    return base64.b64decode(value, validate=True)


def _classify_key_material(data: bytes | bytearray | str) -> str:
    if isinstance(data, str):
        text = data.strip()
        if _looks_like_hex(text):
            return "hex-string"
        try:
            base64.b64decode(text, validate=True)
            return "base64-string"
        except Exception:
            return "plain-string"

    raw = bytes(data)
    if len(raw) == 32:
        return "raw-32-byte-seed"
    if len(raw) == 64:
        return "raw-64-byte-private-key"
    return "raw-bytes"


def _log_key_diagnostics(stage: str, key_material: bytes | bytearray | str) -> None:
    log.info(
        "Key diagnostics | stage=%s type=%s len=%s classification=%s preview=%s",
        stage,
        type(key_material).__name__,
        len(key_material) if hasattr(key_material, "__len__") else "unknown",
        _classify_key_material(key_material),
        _safe_hex_preview(key_material),
    )


def _coerce_private_key_bytes(private_key: bytes | bytearray | str) -> tuple[bytes, str]:
    """
    Normalize stored key material into raw bytes plus an encoding assumption label.

    Supported inputs:
      - raw 32-byte Ed25519 seed
      - raw 64-byte Algorand secret key (seed + public key)
      - hex string / ASCII hex bytes
      - base64 string / ASCII base64 bytes
    """
    assumption = "raw-bytes"
    candidate: bytes
    _log_key_diagnostics("coerce.input", private_key)

    if isinstance(private_key, bytearray):
        candidate = bytes(private_key)
        assumption = "raw-bytearray"
    elif isinstance(private_key, bytes):
        candidate = private_key
        assumption = "raw-bytes"
    elif isinstance(private_key, str):
        text = private_key.strip()
        if _looks_like_hex(text):
            candidate = bytes.fromhex(text)
            assumption = "hex-string"
        else:
            candidate = _logged_b64decode(text, caller="_coerce_private_key_bytes")
            assumption = "base64-string"
    else:
        raise TypeError(f"Unsupported private key type: {type(private_key).__name__}")

    if len(candidate) in (32, 64):
        _log_key_diagnostics("coerce.output.direct", candidate)
        return candidate, assumption

    if isinstance(private_key, (bytes, bytearray)):
        raise ValueError(
            f"Raw private key bytes must be exactly 32 or 64 bytes in _coerce_private_key_bytes; "
            f"got len={len(candidate)} classification={_classify_key_material(candidate)} "
            f"preview={_safe_hex_preview(candidate)}"
        )

    _log_key_diagnostics("coerce.output.fallback", candidate)
    return candidate, assumption


def _normalize_private_key(private_key: bytes | bytearray | str, *, context: str) -> tuple[bytes, bytes, str]:
    """
    Return a normalized tuple of (algorand_private_key_64, ed25519_seed_32, assumption).
    """
    candidate, assumption = _coerce_private_key_bytes(private_key)

    log.info(
        "Private key normalization | context=%s type=%s len=%s assumption=%s candidate_len=%s candidate_preview=%s candidate_classification=%s",
        context,
        type(private_key).__name__,
        len(private_key) if hasattr(private_key, "__len__") else "unknown",
        assumption,
        len(candidate),
        _safe_hex_preview(candidate),
        _classify_key_material(candidate),
    )

    if len(candidate) == 32:
        seed = candidate
        try:
            signing_key = SigningKey(seed)
        except Exception as exc:
            raise ValueError(
                f"Failed to construct Ed25519 SigningKey in {context}: "
                f"classification={_classify_key_material(candidate)} decoded_len={len(candidate)} "
                f"seed_len={len(seed)} preview={_safe_hex_preview(seed)}"
            ) from exc
        verify_key = signing_key.verify_key.encode()
        log.info(
            "Private key normalization result | context=%s mode=seed32 seed_len=%s verify_key_len=%s seed_preview=%s verify_key_preview=%s",
            context,
            len(seed),
            len(verify_key),
            _safe_hex_preview(seed),
            _safe_hex_preview(verify_key),
        )
        return seed + verify_key, seed, f"{assumption}->seed32"

    if len(candidate) == 64:
        seed = candidate[:32]
        log.info(
            "Private key normalization result | context=%s mode=algorand64 seed_len=%s key_len=%s seed_preview=%s key_preview=%s",
            context,
            len(seed),
            len(candidate),
            _safe_hex_preview(seed),
            _safe_hex_preview(candidate),
        )
        return candidate, seed, f"{assumption}->algorand64"

    raise ValueError(
        f"Unsupported private key length after normalization in {context}: "
        f"{len(candidate)} bytes; classification={_classify_key_material(candidate)} "
        f"assumption={assumption} preview={_safe_hex_preview(candidate)}"
    )


def _extract_ed25519_seed(private_key: bytes | bytearray | str, *, context: str) -> tuple[bytes, str]:
    """
    Normalize key material specifically for Ed25519 SigningKey(seed).

    Accepted shapes:
      - 32-byte raw Ed25519 seed
      - 64-byte Algorand private key, where the first 32 bytes are the seed
    """
    key_bytes, assumption = _coerce_private_key_bytes(private_key)
    original_len = len(key_bytes)

    if original_len == 64:
        seed = key_bytes[:32]
        log.info(
            "Ed25519 seed normalization | context=%s original_key_len=%s normalized_seed_len=%s normalized_64_to_32=%s assumption=%s key_preview=%s seed_preview=%s",
            context,
            original_len,
            len(seed),
            True,
            assumption,
            _safe_hex_preview(key_bytes),
            _safe_hex_preview(seed),
        )
        return seed, f"{assumption}->algorand64_to_seed32"

    if original_len == 32:
        log.info(
            "Ed25519 seed normalization | context=%s original_key_len=%s normalized_seed_len=%s normalized_64_to_32=%s assumption=%s seed_preview=%s",
            context,
            original_len,
            original_len,
            False,
            assumption,
            _safe_hex_preview(key_bytes),
        )
        return key_bytes, f"{assumption}->seed32"

    raise ValueError(
        f"Invalid key length for Ed25519 seed normalization in {context}: "
        f"decoded_len={original_len} expected=32_or_64 classification={_classify_key_material(key_bytes)} "
        f"assumption={assumption} preview={_safe_hex_preview(key_bytes)}"
    )


def _to_algosdk_private_key_string(private_key_64: bytes, *, context: str) -> str:
    """
    Adapt a normalized 64-byte Algorand private key into the format expected by
    the installed algosdk: base64-encoded string of the 64 raw key bytes.
    """
    if len(private_key_64) != 64:
        raise ValueError(
            f"Algorand SDK private key adaptation requires 64 bytes in {context}; "
            f"got len={len(private_key_64)} preview={_safe_hex_preview(private_key_64)}"
        )
    encoded = base64.b64encode(private_key_64).decode("ascii")
    log.info(
        "Algorand SDK private key adapted | context=%s input_type=%s input_class=%s input_len=%s output_type=%s output_class=%s output_len=%s expected_format=%s output_preview=%s",
        context,
        type(private_key_64).__name__,
        private_key_64.__class__.__name__,
        len(private_key_64),
        type(encoded).__name__,
        encoded.__class__.__name__,
        len(encoded),
        "base64-string-of-64-byte-private-key",
        _safe_hex_preview(encoded),
    )
    return encoded


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
    normalized_key = None
    sdk_private_key = None
    key_buf = None
    try:
        normalized_key, _, assumption = _normalize_private_key(
            private_key,
            context="sign_transaction",
        )
        log.info(
            "Signing transaction | key_type=%s key_len=%s normalized_len=%s assumption=%s normalized_preview=%s",
            type(private_key).__name__,
            len(private_key) if hasattr(private_key, "__len__") else "unknown",
            len(normalized_key),
            assumption,
            _safe_hex_preview(normalized_key),
        )
        key_buf = bytearray(normalized_key)
        sdk_private_key = _to_algosdk_private_key_string(
            bytes(key_buf),
            context="sign_transaction",
        )
        log.info(
            "Algorand transaction signing call | sdk_function=%s txn_type=%s private_key_type=%s private_key_class=%s expected_format=%s assumption=%s",
            "txn.sign",
            txn.__class__.__name__,
            type(sdk_private_key).__name__,
            sdk_private_key.__class__.__name__,
            "base64 string accepted by algosdk.transaction.Transaction.sign",
            assumption,
        )
        try:
            signed_txn = txn.sign(sdk_private_key)
        except Exception as exc:
            raise ValueError(
                f"Algorand transaction signing failed: normalized_len={len(normalized_key)} "
                f"assumption={assumption} sdk_key_type={type(sdk_private_key).__name__} "
                f"sdk_key_class={sdk_private_key.__class__.__name__} preview={_safe_hex_preview(normalized_key)}"
            ) from exc
    finally:
        if key_buf is not None:
            for i in range(len(key_buf)):
                key_buf[i] = 0
            del key_buf
        if sdk_private_key is not None:
            del sdk_private_key
        if normalized_key is not None:
            del normalized_key
        del private_key
    return signed_txn


def sign_credential_hash(cert_hash: str, institution_id: str | None = None) -> str:
    """
    Sign a certificate / artwork hash using Ed25519 (PyNaCl).

    Uses first 32 bytes of Algorand private key as seed.
    """

    private_key = _load_private_key(institution_id)
    seed = None

    try:
        _log_key_diagnostics("sign_credential_hash.private_key", private_key)
        seed, assumption = _extract_ed25519_seed(
            private_key,
            context="sign_credential_hash",
        )
        log.info(
            "Signing credential hash | key_type=%s key_len=%s normalized_seed_len=%s assumption=%s seed_preview=%s",
            type(private_key).__name__,
            len(private_key) if hasattr(private_key, "__len__") else "unknown",
            len(seed),
            assumption,
            _safe_hex_preview(seed),
        )

        try:
            signing_key = SigningKey(seed)
        except Exception as exc:
            raise ValueError(
                f"Ed25519 SigningKey creation failed in sign_credential_hash: "
                f"seed_len={len(seed)} assumption={assumption} "
                f"seed_classification={_classify_key_material(seed)} preview={_safe_hex_preview(seed)}"
            ) from exc
        signed = signing_key.sign(cert_hash.encode())
        signature = base64.b64encode(signed.signature).decode()
        return signature

    finally:
        if seed is not None:
            del seed
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
    normalized_key = None
    sdk_private_key = None
    key_buf = None
    try:
        normalized_key, _, assumption = _normalize_private_key(
            private_key,
            context="get_issuer_address",
        )
        log.info(
            "Deriving issuer address | key_type=%s key_len=%s normalized_len=%s assumption=%s normalized_preview=%s",
            type(private_key).__name__,
            len(private_key) if hasattr(private_key, "__len__") else "unknown",
            len(normalized_key),
            assumption,
            _safe_hex_preview(normalized_key),
        )
        key_buf = bytearray(normalized_key)
        sdk_private_key = _to_algosdk_private_key_string(
            bytes(key_buf),
            context="get_issuer_address",
        )
        try:
            address = account.address_from_private_key(sdk_private_key)
        except Exception as exc:
            raise ValueError(
                f"Algorand address reconstruction failed: normalized_len={len(normalized_key)} "
                f"assumption={assumption} sdk_key_type={type(sdk_private_key).__name__} "
                f"sdk_key_class={sdk_private_key.__class__.__name__} preview={_safe_hex_preview(normalized_key)}"
            ) from exc
    finally:
        if key_buf is not None:
            for i in range(len(key_buf)):
                key_buf[i] = 0
            del key_buf
        if sdk_private_key is not None:
            del sdk_private_key
        if normalized_key is not None:
            del normalized_key
        del private_key
    return address
