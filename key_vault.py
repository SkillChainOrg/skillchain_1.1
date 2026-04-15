```python
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
  - If KEY_ENCRYPTION_KEY is NOT set, encryption is skipped (dev fallback).

WARNING: This module is NOT suitable for production. Use HCP Vault for production.
"""

import os
import base64
import secrets as sec
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _get_kek() -> Optional[bytes]:
    """
    Load the 32-byte Key-Encryption-Key from the environment.

    Returns:
        bytes: KEK if valid
        None: if not set (dev fallback)

    Raises:
        RuntimeError: If key is set but invalid
    """
    kek_hex = os.getenv("KEY_ENCRYPTION_KEY")

    if not kek_hex:
        print("[Vault] KEY_ENCRYPTION_KEY not set — skipping encryption")
        return None

    try:
        kek = bytes.fromhex(kek_hex)
    except ValueError:
        raise RuntimeError(
            "KEY_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)."
        )

    if len(kek) != 32:
        raise RuntimeError(
            f"KEY_ENCRYPTION_KEY must decode to exactly 32 bytes; got {len(kek)}."
        )

    return kek


def encrypt_key(private_key_bytes: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Encrypt a raw private key with AES-256-GCM.

    If KEY_ENCRYPTION_KEY is not set, encryption is skipped.

    Args:
        private_key_bytes: Raw private key bytes to encrypt.

    Returns:
        (ct_b64, nonce_b64) if encryption succeeds
        (None, None) if encryption is skipped

    CRITICAL — caller contract:
        After this call, delete the plaintext private_key_bytes from your scope.
    """
    kek = _get_kek()

    if not kek:
        print("[Vault] Skipping encryption — no KEK configured")
        return None, None

    nonce = sec.token_bytes(12)  # 96-bit nonce (GCM standard)
    ct = AESGCM(kek).encrypt(nonce, private_key_bytes, None)

    return base64.b64encode(ct).decode(), base64.b64encode(nonce).decode()


def decrypt_key(ct_b64: str, nonce_b64: str) -> bytes:
    """
    Decrypt a private key encrypted by encrypt_key().

    Args:
        ct_b64:    base64-encoded AES-GCM ciphertext
        nonce_b64: base64-encoded 12-byte nonce

    Returns:
        Decrypted private key as raw bytes.

    Raises:
        RuntimeError: If KEY_ENCRYPTION_KEY is not set or invalid
        cryptography.exceptions.InvalidTag: If ciphertext is tampered
    """
    kek = _get_kek()

    if not kek:
        raise RuntimeError("Cannot decrypt: KEY_ENCRYPTION_KEY not set")

    ct = base64.b64decode(ct_b64)
    nonce = base64.b64decode(nonce_b64)

    return AESGCM(kek).decrypt(nonce, ct, None)
