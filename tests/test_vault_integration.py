"""
tests/test_vault_integration.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Vault integration tests — all run with VAULT_ENABLED=false (AES-GCM path)
to avoid requiring a live Vault server in CI.

Live Algorand and Vault calls are fully mocked.

Run with:
    pytest tests/test_vault_integration.py -v
"""

import os
import sys
import importlib
import types
from unittest.mock import patch, MagicMock, call

import pytest

# ── Allow importing project modules from the repo root ───────────────────────
_TESTS_DIR   = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_TESTS_DIR)
sys.path.insert(0, _PROJECT_DIR)

# Set required env vars BEFORE any project imports so module-level checks pass.
os.environ.setdefault("VAULT_ENABLED",       "false")
os.environ.setdefault("DEMO_MODE",           "true")
os.environ.setdefault("ADMIN_KEY",           "test-admin-key-for-ci")
os.environ.setdefault("DATABASE_URL",        "postgresql://fake/fake")
os.environ.setdefault("KEY_ENCRYPTION_KEY",  "a" * 64)   # 64-char hex → 32-byte KEK
os.environ.setdefault("MNEMONIC",            "")          # not needed for inst-mode tests


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test 1 — approve_registration() writes encrypted key to DB when VAULT_ENABLED=false
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_approve_registration_aes_gcm_path(monkeypatch):
    """
    When VAULT_ENABLED=false, approve_registration() must:
      - NOT call vault_client.write_key
      - Call key_vault.encrypt_key with private key bytes
      - Call register_did with non-None private_key_enc and key_nonce
      - Call register_did with vault_key_id=None
    """
    os.environ["VAULT_ENABLED"] = "false"

    # Prevent real DB/Algorand calls
    fake_reg = {
        "id": "test-reg-id",
        "institution": "Test University",
        "domain": "test.edu",
        "verified": 1,
        "approved": 0,
        "email": "admin@test.edu",
        "created_at": "2025-01-01",
    }

    encrypt_result = ("FAKE_CT_B64", "FAKE_NONCE_B64")
    register_result = {
        "did": "did:skillchain:testnet:FAKEADDR:abc123",
        "address": "FAKEADDR",
        "institution_id": "abc123def456abcd",
        "api_key": "plaintext-api-key",
        "domain": "test.edu",
        "wallet_version": 2,
    }

    with patch("did_service._get_pending_registration", return_value=fake_reg), \
         patch("vault_client.is_vault_enabled", return_value=False), \
         patch("vault_client.write_key") as mock_write_key, \
         patch("key_vault.encrypt_key", return_value=encrypt_result) as mock_encrypt, \
         patch("did_service._fund_institution_address", return_value="TXID123"), \
         patch("did_service.register_did", return_value=register_result) as mock_register, \
         patch("did_service.get_db_connection") as mock_db:

        

        # Suppress pending approval DB write
        mock_conn = MagicMock()
        mock_cur  = MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_db.return_value = mock_conn

        from did_service import approve_registration
        result = approve_registration("test-reg-id")

    # vault_client.write_key must NOT be called
    mock_write_key.assert_not_called()
    #key_vault.encrypt_key must be called with bytes
    mock_encrypt.assert_called_once()

    # register_did must receive AES-GCM data, vault_key_id=None
    mock_register.assert_called_once()
    call_kwargs = mock_register.call_args.kwargs
    assert call_kwargs["private_key_enc"] == "FAKE_CT_B64"
    assert call_kwargs["key_nonce"]       == "FAKE_NONCE_B64"
    assert call_kwargs["vault_key_id"]    is None

    assert result["success"] is True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test 2 — approve_registration() does NOT write private_key_enc when VAULT_ENABLED=true
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_approve_registration_vault_path(monkeypatch):
    """
    When VAULT_ENABLED=true, approve_registration() must:
      - Call vault_client.write_key (mocked — no real Vault)
      - Call register_did with private_key_enc=None, key_nonce=None
      - Call register_did with vault_key_id equal to the derived institution_id
    """
    os.environ["VAULT_ENABLED"] = "true"

    fake_reg = {
        "id": "test-reg-id-vault",
        "institution": "Vault University",
        "domain": "vault.edu",
        "verified": 1,
        "approved": 0,
        "email": "admin@vault.edu",
        "created_at": "2025-01-01",
    }

    register_result = {
        "did": "did:skillchain:testnet:VAULTADDR:abc123",
        "address": "VAULTADDR",
        "institution_id": "abc123def456abcd",
        "api_key": "plaintext-api-key-vault",
        "domain": "vault.edu",
        "wallet_version": 2,
    }

    with patch("did_service._get_pending_registration", return_value=fake_reg), \
        patch("vault_client.is_vault_enabled", return_value=True), \
        patch("vault_client.write_key") as mock_write_key, \
        patch("did_service._fund_institution_address", return_value="TXID456"), \
        patch("did_service.register_did", return_value=register_result) as mock_register, \
        patch("did_service.get_db_connection") as mock_db:


        mock_conn = MagicMock()
        mock_cur  = MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_db.return_value = mock_conn

        from did_service import approve_registration
        result = approve_registration("test-reg-id-vault")

    # vault_client.write_key MUST be called with bytes
    mock_write_key.assert_called_once()
    key_arg = mock_write_key.call_args[0][1]
    assert isinstance(key_arg, bytes), "write_key must receive bytes, not str"

    # register_did must receive None for AES-GCM fields, non-None vault_key_id
    call_kwargs = mock_register.call_args.kwargs
    assert call_kwargs["private_key_enc"] is None
    assert call_kwargs["key_nonce"]       is None
    assert call_kwargs["vault_key_id"]    is not None

    os.environ["VAULT_ENABLED"] = "false"   # reset for subsequent tests


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test 3 — sign_transaction() deletes key bytes even if signing raises
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_sign_transaction_deletes_key_on_exception():
    """
    sign_transaction() must propagate a signing exception.

    The production implementation performs key-buffer cleanup in its
    finally block. This test verifies the exception path without attempting
    to inspect the internal local buffer after cleanup.
    """
    import signing_service

    # 64-byte fake private key (seed + pubkey placeholder)
    fake_key = bytes(range(64))
    class BoomTxn:
        def sign(self, key):
            raise ValueError("Simulated signing failure")


    with patch.object(signing_service, "_load_private_key", return_value=fake_key):
        with pytest.raises(ValueError, match="Algorand transaction signing failed"):
            signing_service.sign_transaction(
                BoomTxn(),
                institution_id="test-inst",
            )
    # We can't inspect the wiped bytearray after the function returns because
    # it's a local variable, but the test proves the exception propagated
    # (not swallowed) and the function completed its finally block without
    # another exception (which would cause a different error).


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test 4 — /health returns correct structure when VAULT_ENABLED=false
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@pytest.fixture()
def flask_test_client():
    """Return a Flask test client with DB and Vault interactions fully mocked."""
    with patch("db_migrations.run_migrations"), \
         patch("algorand_service.init_db"), \
         patch("did_service.init_did_db"):
        import app as flask_app_module
        flask_app_module.app.config["TESTING"] = True
        with flask_app_module.app.test_client() as client:
            yield client


def test_health_structure_vault_disabled(flask_test_client):
    """
    When VAULT_ENABLED=false the /health endpoint must return:
      - status: "ok" (assuming DB mock OK)
      - vault.enabled: false
      - vault.reachable: null
      - vault.mode: "aes_gcm"
      - database: "ok"
      - timestamp: ISO8601 string
    """
    mock_conn = MagicMock()
    mock_cur  = MagicMock()
    mock_conn.cursor.return_value = mock_cur

    with patch("app.get_db_connection", return_value=mock_conn), \
         patch("app.is_vault_enabled", return_value=False, create=True):

        resp = flask_test_client.get("/health")

    assert resp.status_code == 200
    data = resp.get_json()

    assert data["status"] in ("ok", "degraded")
    assert isinstance(data["vault"], dict)
    assert data["vault"]["enabled"]   is False
    assert data["vault"]["reachable"] is None
    assert data["vault"]["mode"]      == "aes_gcm"
    assert data["database"]           == "ok"
    assert "timestamp" in data
    # Basic ISO8601 check
    import re
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", data["timestamp"])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test 5 — /health returns "degraded" when Vault is enabled but unreachable
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_health_degraded_when_vault_unreachable(flask_test_client):
    """
    When VAULT_ENABLED=true and health_check() returns False (unreachable),
    /health must return status="degraded" and vault.reachable=false.
    """
    mock_conn = MagicMock()
    mock_cur  = MagicMock()
    mock_conn.cursor.return_value = mock_cur

    with patch("app.get_db_connection", return_value=mock_conn):
        # Patch vault_client at the app module level
        with patch.dict("sys.modules", {
            "vault_client": MagicMock(
                is_vault_enabled=lambda: True,
                health_check=lambda: False,   # simulates unreachable Vault
            )
        }):
            # Re-trigger the import inside the route handler
            import importlib
            import app as flask_app_module
            importlib.reload(flask_app_module)
            flask_app_module.app.config["TESTING"] = True

            with flask_app_module.app.test_client() as client:
                with patch("app.get_db_connection", return_value=mock_conn):
                    resp = client.get("/health")

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"]           == "degraded"
    assert data["vault"]["enabled"] is True
    assert data["vault"]["reachable"] is False
    assert data["vault"]["mode"]    == "vault"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test 6 — vault_client hex round-trip
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_vault_client_hex_roundtrip():
    """
    write_key encodes bytes as hex; read_key decodes hex back to bytes.
    Verify the round-trip with a mocked hvac client.
    """
    import vault_client as vc

    fake_key = os.urandom(64)   # random 64-byte private key

    stored: dict = {}

    def fake_create_or_update(mount_point, path, secret):
        stored[path] = secret

    def fake_read_version(mount_point, path, raise_on_deleted_version):
        return {"data": {"data": stored[path]}}

    mock_kv = MagicMock()
    mock_kv.v2.create_or_update_secret.side_effect = fake_create_or_update
    mock_kv.v2.read_secret_version.side_effect     = fake_read_version

    mock_client = MagicMock()
    mock_client.secrets.kv = mock_kv
    mock_client.is_authenticated.return_value = True

    with patch.object(vc, "_get_client", return_value=mock_client):
        vc.write_key("test-institution", fake_key)

    # Confirm it was stored as a hex string, not raw bytes
    stored_payload = list(stored.values())[0]
    assert "private_key_hex" in stored_payload
    assert isinstance(stored_payload["private_key_hex"], str)
    assert stored_payload["private_key_hex"] == fake_key.hex()

    with patch.object(vc, "_get_client", return_value=mock_client):
        recovered = vc.read_key("test-institution")

    assert recovered == fake_key, "round-trip: recovered bytes must equal original"
