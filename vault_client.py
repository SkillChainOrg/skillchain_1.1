"""
vault_client.py — HashiCorp Vault KV v2 client for SkillChain key management.

Contract:
  - When VAULT_ENABLED=true, Vault is the source of truth for private key bytes.
  - All key operations raise explicit exceptions (no silent None returns).
  - Keys are stored at KV v2 path: secret/skillchain/{institution_id}
  - Key material is never logged.
"""

import os
import hvac
from dotenv import load_dotenv
import logging

load_dotenv()

# --- Vault configuration from environment variables ---
_VAULT_ADDR      = os.getenv("VAULT_URL") or os.getenv("VAULT_ADDR") or "http://127.0.0.1:8200"
_VAULT_TOKEN     = os.getenv("VAULT_TOKEN")
_VAULT_NAMESPACE = os.getenv("VAULT_NAMESPACE")  # Optional: for HCP Vault namespaces
_VAULT_ENABLED   = os.getenv("VAULT_ENABLED", "false").lower() == "true"

# KV v2 mount point and path prefix — matches Vault policy paths
_MOUNT_POINT = "secret"
_KV_PREFIX   = "skillchain"

log = logging.getLogger(__name__)


def _safe_preview(value: str | bytes | bytearray | None, limit: int = 8) -> str:
    if value is None:
        return "none"
    if isinstance(value, str):
        return value[: limit * 2] or "empty-str"
    raw = bytes(value[:limit])
    return raw.hex() if raw else "empty"


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

    try:
        client = hvac.Client(**kwargs)
    except Exception as exc:
        raise RuntimeError(f"Vault connection failure: {_VAULT_ADDR}") from exc

    try:
        if not client.is_authenticated():
            raise RuntimeError(
                "Vault authentication failed. Verify VAULT_URL/VAULT_ADDR is reachable and VAULT_TOKEN is valid."
            )
    except Exception as exc:
        raise RuntimeError("Vault authentication check failed") from exc

    return client


def _path_for(institution_id: str) -> str:
    if not institution_id:
        raise ValueError("institution_id is required")
    return f"{_KV_PREFIX}/{institution_id}"


def write_key(institution_id: str, key_bytes: bytes) -> None:
    """
    Write private key bytes to Vault KV v2 at secret/skillchain/{institution_id}.

    Keys are stored as HEX strings so they are safe for JSON serialisation.
    (Vault KV v2 uses a JSON payload; raw bytes are not JSON-serialisable.)
    """
    if not isinstance(key_bytes, (bytes, bytearray)):
        raise TypeError(f"key_bytes must be bytes, got {type(key_bytes).__name__}")
    path = _path_for(institution_id)
    client = _get_client()
    try:
        client.secrets.kv.v2.create_or_update_secret(
            mount_point=_MOUNT_POINT,
            path=path,
            secret={"private_key_hex": key_bytes.hex()},  # hex string is JSON-safe
        )
        log.info("Vault write succeeded for institution_id=%s path=%s/%s",
                 institution_id, _MOUNT_POINT, path)
    except hvac.exceptions.Forbidden as exc:
        raise PermissionError(f"Vault write forbidden for path '{_MOUNT_POINT}/{path}'") from exc
    except Exception as exc:
        log.error("Vault write failed for institution_id=%s path=%s: %s", institution_id, path, exc)
        raise RuntimeError(f"Vault write failed for institution_id='{institution_id}'") from exc


def read_key(institution_id: str) -> bytes:
    """
    Read private key bytes from Vault KV v2 at secret/skillchain/{institution_id}.

    Supports both the current format (``private_key_hex`` — hex string) and the
    legacy format (``private_key_bytes`` — raw bytes that hvac may have stored as
    a base64-encoded string depending on the client version) for backward
    compatibility.
    """
    path = _path_for(institution_id)
    client = _get_client()
    try:
        resp = client.secrets.kv.v2.read_secret_version(
            mount_point=_MOUNT_POINT,
            path=path,
            raise_on_deleted_version=True,
        )
        data = resp["data"]["data"]

        # Preferred format written by write_key() — hex string
        hex_val = data.get("private_key_hex")
        if hex_val is not None:
            if not isinstance(hex_val, str):
                raise RuntimeError(
                    f"Vault private_key_hex has unexpected type {type(hex_val).__name__} "
                    f"at '{_MOUNT_POINT}/{path}'"
                )
            try:
                key = bytes.fromhex(hex_val)
                log.info(
                    "Vault key read | institution_id=%s source=private_key_hex raw_len=%s decoded_len=%s preview=%s",
                    institution_id,
                    len(hex_val),
                    len(key),
                    key[:8].hex() if key else "empty",
                )
                return key
            except ValueError as exc:
                raise RuntimeError(
                    f"Vault private_key_hex is not valid hex at '{_MOUNT_POINT}/{path}'"
                ) from exc

        # Legacy fallback: raw bytes field (may never exist in practice, but handle cleanly)
        raw_val = data.get("private_key_bytes")
        if raw_val is not None:
            if isinstance(raw_val, (bytes, bytearray)):
                log.warning(
                    "Vault key for institution_id=%s uses legacy bytes format; "
                    "re-run migrate_keys_to_vault to upgrade.", institution_id
                )
                key = bytes(raw_val)
                log.info(
                    "Vault key read | institution_id=%s source=private_key_bytes.bytes decoded_len=%s preview=%s",
                    institution_id,
                    len(key),
                    key[:8].hex() if key else "empty",
                )
                return key
            if isinstance(raw_val, str):
                # hvac may have stored bytes as a hex or base64 string depending on version
                import base64 as _b64
                try:
                    key = bytes.fromhex(raw_val)
                    log.info(
                        "Vault key read | institution_id=%s source=private_key_bytes.hex raw_len=%s decoded_len=%s preview=%s",
                        institution_id,
                        len(raw_val),
                        len(key),
                        key[:8].hex() if key else "empty",
                    )
                    return key
                except ValueError:
                    pass
                try:
                    log.info(
                        "Base64 decode attempt | caller=vault_client.read_key.private_key_bytes.base64 type=%s len=%s preview=%s",
                        type(raw_val).__name__,
                        len(raw_val),
                        _safe_preview(raw_val),
                    )
                    key = _b64.b64decode(raw_val)
                    log.info(
                        "Vault key read | institution_id=%s source=private_key_bytes.base64 raw_len=%s decoded_len=%s preview=%s",
                        institution_id,
                        len(raw_val),
                        len(key),
                        key[:8].hex() if key else "empty",
                    )
                    return key
                except Exception:
                    pass  # not base64 — fall through to error

        raise KeyError(f"Vault key payload missing at '{_MOUNT_POINT}/{path}'")

    except KeyError:
        raise
    except hvac.exceptions.InvalidPath as exc:
        raise KeyError(f"No Vault key found at '{_MOUNT_POINT}/{path}'") from exc
    except hvac.exceptions.Forbidden as exc:
        raise PermissionError(f"Vault read forbidden for path '{_MOUNT_POINT}/{path}'") from exc
    except (RuntimeError, PermissionError):
        raise
    except Exception as exc:
        log.error("Vault read failed for institution_id=%s path=%s: %s", institution_id, path, exc)
        raise RuntimeError(f"Vault read failed for institution_id='{institution_id}'") from exc


def delete_key(institution_id: str) -> None:
    """
    Delete all versions and metadata for an institution key.
    """
    path = _path_for(institution_id)
    client = _get_client()
    try:
        client.secrets.kv.v2.delete_metadata_and_all_versions(
            mount_point=_MOUNT_POINT,
            path=path,
        )
    except hvac.exceptions.Forbidden as exc:
        raise PermissionError(f"Vault delete forbidden for path '{_MOUNT_POINT}/{path}'") from exc
    except hvac.exceptions.InvalidPath as exc:
        raise KeyError(f"No Vault key metadata found at '{_MOUNT_POINT}/{path}'") from exc
    except Exception as exc:
        log.error("Vault delete failed for institution_id=%s path=%s: %s", institution_id, path, exc)
        raise RuntimeError(f"Vault delete failed for institution_id='{institution_id}'") from exc


def health_check() -> bool:
    """
    Return True iff Vault is reachable and unsealed.

    Never raises — all exceptions are caught and logged. Should be called
    only when VAULT_ENABLED=true; returns False immediately otherwise.
    """
    if not is_vault_enabled():
        return False
    try:
        client = _get_client()
    except Exception as exc:
        log.warning("Vault health_check: connection/auth failed — %s", exc)
        return False
    try:
        sealed = client.sys.is_sealed()
        return sealed is False
    except Exception as exc:
        log.warning("Vault health_check: is_sealed() call failed — %s", exc)
        return False


# Backwards-compatible aliases (older modules)
store_key = write_key
fetch_key = read_key
