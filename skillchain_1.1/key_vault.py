"""
key_vault.py — AES-256-GCM symmetric key encryption for dev-mode fallback.

Used ONLY when VAULT_ENABLED=false (local development or hackathon without HCP Vault).
In production (VAULT_ENABLED=true), private keys live exclusively in HashiCorp Vault
and this module is never called.

Security design:
  - A single Key-Encryption-Key (KEK) is loaded from KEY_ENCRYPTION_KEY env var.
  - Each institution private key is encrypted with a unique random 12-byte nonce.
  - Ciphertext and nonce are stored as base64 in did_registry columns
    (private_key_enc, key_nonce) — the raw private key bytes never persist.
  - The KEK must be a 32-byte (64 hex-char) secret generated with:
        python -c "import secrets; print(secrets.token_hex(32))"

WARNING: This module is NOT suitable for production. Use HCP Vault for production.
"""

import os
import base64
import secrets as sec

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEK_HEX = os.getenv("KEY_ENCRYPTION_KEY")


def _get_kek() -> bytes:
    """
    Load the 32-byte Key-Encryption-Key from the environment.

    Raises:
        RuntimeError: If KEY_ENCRYPTION_KEY is not set or is not 64 hex characters.
    """
    if not _KEK_HEX:
        raise RuntimeError(
            "KEY_ENCRYPTION_KEY not set — required for dev-mode key storage. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    try:
        kek = bytes.fromhex(_KEK_HEX)
    except ValueError:
        raise RuntimeError(
            "KEY_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)."
        )
    if len(kek) != 32:
        raise RuntimeError(
            f"KEY_ENCRYPTION_KEY must decode to exactly 32 bytes; got {len(kek)}."
        )
    return kek


def encrypt_key(private_key_bytes: bytes) -> tuple[str, str]:
    """
    Encrypt a raw private key with AES-256-GCM.

    A fresh 12-byte nonce is generated for every call, so the same key
    encrypted twice produces different ciphertext — no nonce reuse.

    Args:
        private_key_bytes: Raw private key bytes to encrypt.

    Returns:
        (ct_b64, nonce_b64): base64-encoded ciphertext and nonce, both safe
        to store in the database as TEXT columns.

    CRITICAL — caller contract:
        After this call, delete the plaintext private_key_bytes from your scope.
        Example:
            ct_b64, nonce_b64 = encrypt_key(private_key_bytes)
            del private_key_bytes
    """
    nonce = sec.token_bytes(12)   # 96-bit nonce — GCM standard
    ct = AESGCM(_get_kek()).encrypt(nonce, private_key_bytes, None)
    return base64.b64encode(ct).decode(), base64.b64encode(nonce).decode()


def decrypt_key(ct_b64: str, nonce_b64: str) -> bytes:
    """
    Decrypt a private key encrypted by encrypt_key().

    Args:
        ct_b64:    base64-encoded AES-GCM ciphertext (from did_registry.private_key_enc).
        nonce_b64: base64-encoded 12-byte nonce (from did_registry.key_nonce).

    Returns:
        Decrypted private key as raw bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If ciphertext has been tampered with.
        RuntimeError: If KEY_ENCRYPTION_KEY is not set or invalid.

    CRITICAL — caller contract:
        The returned bytes MUST be deleted from the caller's scope immediately
        after use. Never log, cache, or return raw key bytes further up the call stack.
    """
    ct = base64.b64decode(ct_b64)
    nonce = base64.b64decode(nonce_b64)
    return AESGCM(_get_kek()).decrypt(nonce, ct, None)
