"""
key_vault.py — AES-256-GCM symmetric key encryption for dev-mode fallback.

Used ONLY when VAULT_ENABLED=false (local development without HCP Vault).
In production (VAULT_ENABLED=true), private keys live exclusively in HashiCorp Vault
and this module is never called.

Security design:
  - KEK is loaded from KEY_ENCRYPTION_SECRET (preferred) or KEY_ENCRYPTION_KEY (legacy alias).
  - Raises RuntimeError if neither variable is set.
    Never silently proceeds without encryption — no (None, None) fallback.
  - Each private key is encrypted with a unique random 12-byte nonce (AES-256-GCM).
  - Ciphertext and nonce are stored as base64; raw key bytes never persist to disk.
  - Key lifetime in memory: bytes are returned to the caller and MUST be deleted
    immediately after use. Never log, return to a client, or store the result.

KEY_ENCRYPTION_SECRET env var:
  Generate:  python -c "import secrets; print(secrets.token_hex(32))"
  Add to .env:  KEY_ENCRYPTION_SECRET=<64-char hex>

WARNING: This module is NOT suitable for production. Use HCP Vault for production.
"""

import os
import base64
import secrets as sec
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _get_kek() -> bytes:
    """
    Load the 32-byte Key-Encryption-Key from the environment.

    Resolution order:
        1. KEY_ENCRYPTION_SECRET  (preferred — artisan-first naming)
        2. KEY_ENCRYPTION_KEY     (legacy alias — backward-compatible)

    Raises:
        RuntimeError: If neither variable is set or if the value is malformed.
                      Never returns None — always encrypts or fails hard.

    Note: Called only when VAULT_ENABLED=false.
          When Vault is enabled, private keys never touch this module.
    """
    kek_hex = os.getenv("KEY_ENCRYPTION_SECRET") or os.getenv("KEY_ENCRYPTION_KEY")

    if not kek_hex:
        raise RuntimeError(
            "KEY_ENCRYPTION_SECRET is not set.\n"
            "This is required for AES-GCM key storage when VAULT_ENABLED=false.\n"
            "Generate one:  python -c \"import secrets; print(secrets.token_hex(32))\"\n"
            "Then add:      KEY_ENCRYPTION_SECRET=<value>  to your .env file.\n"
            "For production: set VAULT_ENABLED=true and configure HashiCorp Vault instead."
        )

    try:
        kek = bytes.fromhex(kek_hex)
    except ValueError:
        raise RuntimeError(
            f"KEY_ENCRYPTION_SECRET must be a 64-character hex string (32 bytes). "
            f"Got {len(kek_hex)} characters — check for truncation or whitespace."
        )

    if len(kek) != 32:
        raise RuntimeError(
            f"KEY_ENCRYPTION_SECRET must decode to exactly 32 bytes; got {len(kek)}. "
            "Regenerate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    return kek


def encrypt_key(private_key_bytes: bytes) -> Tuple[str, str]:
    """
    Encrypt a raw private key with AES-256-GCM.

    Always encrypts — raises RuntimeError if KEY_ENCRYPTION_SECRET is not set.
    There is NO silent fallback to unencrypted storage.

    Args:
        private_key_bytes: Raw private key bytes to encrypt.

    Returns:
        (ct_b64, nonce_b64) — both base64-encoded strings, always populated.

    CRITICAL — caller contract:
        Delete private_key_bytes from the calling scope immediately after this call.
        Key lifetime MUST be limited to the encryption call only.
    """
    kek   = _get_kek()                           # raises if not set
    nonce = sec.token_bytes(12)                  # 96-bit nonce (GCM standard)
    ct    = AESGCM(kek).encrypt(nonce, private_key_bytes, None)

    return base64.b64encode(ct).decode(), base64.b64encode(nonce).decode()


def decrypt_key(ct_b64: str, nonce_b64: str) -> bytes:
    """
    Decrypt a private key previously encrypted by encrypt_key().

    Args:
        ct_b64:    base64-encoded AES-GCM ciphertext.
        nonce_b64: base64-encoded 12-byte GCM nonce.

    Returns:
        Decrypted private key as raw bytes.

    Raises:
        RuntimeError:                    If KEY_ENCRYPTION_SECRET is not set.
        cryptography.exceptions.InvalidTag: If ciphertext has been tampered with.

    CRITICAL — caller contract:
        Delete the returned bytes immediately after the signing operation.
        Key lifetime MUST be limited to a single signing call.
    """
    kek   = _get_kek()
    ct    = base64.b64decode(ct_b64)
    nonce = base64.b64decode(nonce_b64)
    return AESGCM(kek).decrypt(nonce, ct, None)
