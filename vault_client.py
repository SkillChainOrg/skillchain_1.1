"""
vault_client.py — HashiCorp Vault integration for SkillChain key management.

Security design:
  - Private keys are stored in Vault KV v2 at: secret/skillchain/{institution_id}
  - The system-level issuer (shared wallet) uses path: secret/skillchain/system
  - VAULT_ENABLED=true enforces Vault; fails hard if unreachable (no silent fallback).
  - VAULT_ENABLED=false permits MNEMONIC env var for local development only.
  - No key material is ever logged or printed.
"""

import os
import hvac
from dotenv import load_dotenv

load_dotenv()

# --- Vault configuration from environment variables ---
_VAULT_ADDR      = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
_VAULT_TOKEN     = os.getenv("VAULT_TOKEN")
_VAULT_NAMESPACE = os.getenv("VAULT_NAMESPACE")  # Optional: for HCP Vault namespaces
_VAULT_ENABLED   = os.getenv("VAULT_ENABLED", "false").lower() == "true"

# KV v2 mount point and path prefix — matches Vault policy paths
_MOUNT_POINT = "secret"
_KV_PREFIX   = "skillchain"


def is_vault_enabled() -> bool:
    """Return True when Vault is the active key backend."""
    return _VAULT_ENABLED


def _get_client() -> hvac.Client:
    """
    Construct and authenticate a Vault client.

    Fails hard (RuntimeError) if:
      - VAULT_TOKEN is not set
      - Vault is unreachable or token is invalid

    Security: Token is never logged. No fallback to any other key source.
    """
    if not _VAULT_TOKEN:
        raise RuntimeError(
            "VAULT_TOKEN is not configured. "
            "Set VAULT_TOKEN in your environment when VAULT_ENABLED=true."
        )

    kwargs: dict = {"url": _VAULT_ADDR, "token": _VAULT_TOKEN}
    if _VAULT_NAMESPACE:
        kwargs["namespace"] = _VAULT_NAMESPACE

    client = hvac.Client(**kwargs)

    # Validate authentication immediately — fail hard rather than discover it at sign time
    if not client.is_authenticated():
        raise RuntimeError(
            "Vault authentication failed. "
            "Verify VAULT_ADDR is reachable and VAULT_TOKEN is valid."
        )

    return client


def store_key(institution_id: str, private_key_b64: str) -> None:
    """
    Persist an institution's private key in Vault.

    Vault path: secret/skillchain/{institution_id}

    Args:
        institution_id: Stable identifier derived from the institution's DID suffix.
        private_key_b64: Base64-encoded private key (algosdk format).

    Security:
        - Key is written once at registration time; never returned here.
        - The caller should delete private_key_b64 from memory immediately after this call.
        - This function does NOT log the key value.
    """
    client = _get_client()
    path = f"{_KV_PREFIX}/{institution_id}"

    client.secrets.kv.v2.create_or_update_secret(
        mount_point=_MOUNT_POINT,
        path=path,
        secret={"private_key": private_key_b64},
    )


def fetch_key(institution_id: str) -> str:
    """
    Retrieve an institution's private key from Vault.

    Returns the base64-encoded private key string.

    CRITICAL — caller contract:
        The returned value MUST be deleted from the caller's local scope
        (via `del`) immediately after use. Never log, cache, or return it further up.

    Args:
        institution_id: Vault path segment (e.g. the 16-char DID suffix or "system").

    Raises:
        KeyError:    If no key exists for the given institution_id.
        RuntimeError: If Vault is unreachable or authentication fails.
    """
    client = _get_client()
    path = f"{_KV_PREFIX}/{institution_id}"

    try:
        response = client.secrets.kv.v2.read_secret_version(
            mount_point=_MOUNT_POINT,
            path=path,
            raise_on_deleted_version=True,
        )
        # Extract only the private key value; never log the response object
        return response["data"]["data"]["private_key"]

    except hvac.exceptions.InvalidPath:
        raise KeyError(
            f"No Vault key found for institution_id='{institution_id}'. "
            f"Ensure the key was stored at '{_MOUNT_POINT}/{path}'."
        )


def delete_key(institution_id: str) -> None:
    """
    Permanently hard-delete all versions of an institution's key from Vault.

    Use during institution off-boarding or key rotation.

    Args:
        institution_id: Vault path segment identifying the institution.
    """
    client = _get_client()
    path = f"{_KV_PREFIX}/{institution_id}"

    client.secrets.kv.v2.delete_metadata_and_all_versions(
        mount_point=_MOUNT_POINT,
        path=path,
    )
