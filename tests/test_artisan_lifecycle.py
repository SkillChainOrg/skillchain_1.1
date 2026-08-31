"""Focused tests for the authoritative artisan lifecycle state machine."""

from io import BytesIO
import sys
from types import SimpleNamespace

import pytest

import app as skillchain_app


class _Cursor:
    def __init__(self, rowcount):
        self.rowcount = rowcount

    def execute(self, *_args):
        pass

    def close(self):
        pass


class _Connection:
    def __init__(self, rowcount):
        self.cursor_obj = _Cursor(rowcount)
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


@pytest.mark.parametrize(
    ("current", "new"),
    [
        ("APPLIED", "APPROVED"),
        ("APPLIED", "REJECTED"),
        ("APPROVED", "WALLET_PROVISIONED"),
        ("WALLET_PROVISIONED", "DID_ISSUED"),
        ("DID_ISSUED", "ACTIVE"),
        ("ACTIVE", "SUSPENDED"),
        ("ACTIVE", "REVOKED"),
        ("SUSPENDED", "ACTIVE"),
        ("SUSPENDED", "REVOKED"),
    ],
)
def test_legal_lifecycle_transition_is_atomic(monkeypatch, current, new):
    connection = _Connection(1)
    monkeypatch.setattr(skillchain_app, "get_db_connection", lambda: connection)

    assert skillchain_app.transition_artisan_lifecycle("artisan/test", current, new)
    assert connection.committed is True
    assert connection.rolled_back is False


@pytest.mark.parametrize(
    ("current", "new"),
    [
        ("APPLIED", "ACTIVE"),
        ("APPLIED", "DID_ISSUED"),
        ("APPROVED", "ACTIVE"),
        ("APPROVED", "DID_ISSUED"),
        ("REJECTED", "ACTIVE"),
        ("REVOKED", "ACTIVE"),
        ("ACTIVE", "APPROVED"),
        ("ACTIVE", "APPLIED"),
    ],
)
def test_invalid_lifecycle_transition_is_rejected_without_database_write(
    monkeypatch, current, new
):
    monkeypatch.setattr(
        skillchain_app,
        "get_db_connection",
        lambda: pytest.fail("invalid transitions must not access the database"),
    )

    with pytest.raises(ValueError):
        skillchain_app.transition_artisan_lifecycle("artisan/test", current, new)


def test_concurrent_transition_allows_only_one_winner(monkeypatch):
    connections = iter((_Connection(1), _Connection(0)))
    monkeypatch.setattr(skillchain_app, "get_db_connection", lambda: next(connections))

    assert skillchain_app.transition_artisan_lifecycle("artisan/test", "APPLIED", "APPROVED")
    assert not skillchain_app.transition_artisan_lifecycle("artisan/test", "APPLIED", "APPROVED")


class _EndpointCursor:
    """Small stateful DB double for the two lifecycle HTTP endpoints."""

    def __init__(self, database):
        self.database = database
        self.rowcount = 0
        self._row = None

    def execute(self, query, params=None):
        normalized = " ".join(query.upper().split())
        self.rowcount = 0
        self._row = None

        if "SELECT ARTISAN_ID, LIFECYCLE_STATE FROM ARTISANS WHERE ID" in normalized:
            row = self.database.rows_by_id.get(params[0])
            self._row = (
                {"artisan_id": row["artisan_id"], "lifecycle_state": row["lifecycle_state"]}
                if row else None
            )
        elif "SELECT ID, ARTISAN_ID, NAME, ALGORAND_WALLET, STATUS, LIFECYCLE_STATE" in normalized:
            self._row = self.database.rows_by_did.get(params[0])
        elif "UPDATE ARTISANS SET LIFECYCLE_STATE" in normalized:
            new_state, artisan_id, expected_state = params
            for row in self.database.rows_by_id.values():
                if row["artisan_id"] == artisan_id and row["lifecycle_state"] == expected_state:
                    row["lifecycle_state"] = new_state
                    self.rowcount = 1
                    break
        elif "UPDATE ARTISANS SET STATUS = 'APPROVED'" in normalized:
            approved_by, approved_at, artisan_db_id = params
            row = self.database.rows_by_id[artisan_db_id]
            if row["lifecycle_state"] == "APPROVED":
                row.update(status="approved", approved_by=approved_by, approved_at=approved_at)
                self.rowcount = 1
        elif "INSERT INTO ARTWORKS" in normalized:
            self.database.artwork_inserted = True
            self.rowcount = 1
        elif "SELECT ID FROM ARTWORKS WHERE CERT_HASH" in normalized:
            self._row = {"id": 1}
        else:
            raise AssertionError(f"Unexpected endpoint query: {query}")

    def fetchone(self):
        return self._row

    def close(self):
        pass


class _EndpointDatabase:
    def __init__(self, lifecycle_state="APPLIED"):
        row = {
            "id": 1,
            "artisan_id": "artisan/test-identity",
            "did": "did:skillchain:testnet:wallet:test-identity",
            "name": "Asha Patel",
            "algorand_wallet": "UNCHANGED-WALLET",
            "status": "pending",
            "lifecycle_state": lifecycle_state,
        }
        self.rows_by_id = {row["id"]: row}
        self.rows_by_did = {row["did"]: row}
        self.artwork_inserted = False

    def cursor(self):
        return _EndpointCursor(self)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


@pytest.fixture
def lifecycle_endpoint_db(monkeypatch):
    database = _EndpointDatabase()
    monkeypatch.setattr(skillchain_app, "get_db_connection", lambda: database)
    monkeypatch.setattr(skillchain_app, "dict_cursor", lambda conn: conn.cursor())
    monkeypatch.setattr(skillchain_app, "ADMIN_KEY", "lifecycle-test-admin")
    skillchain_app.app.config["TESTING"] = True
    if hasattr(skillchain_app.limiter, "reset"):
        skillchain_app.limiter.reset()
    return database


def _provisioning_must_not_run(monkeypatch):
    def fail(*_args, **_kwargs):
        pytest.fail("approval must not invoke identity provisioning")

    monkeypatch.setattr(skillchain_app, "_build_artisan_signing_key", fail)
    monkeypatch.setattr(skillchain_app, "build_skillchain_did", fail)
    monkeypatch.setattr(skillchain_app, "_fund_demo_artisan_wallet_if_needed", fail)
    monkeypatch.setitem(sys.modules, "vault_client", SimpleNamespace(write_key=fail))
    monkeypatch.setitem(sys.modules, "key_vault", SimpleNamespace(encrypt_key=fail))


def test_admin_approval_endpoint_transitions_only_to_approved_without_provisioning(
    lifecycle_endpoint_db, monkeypatch
):
    _provisioning_must_not_run(monkeypatch)
    before = dict(lifecycle_endpoint_db.rows_by_id[1])

    with skillchain_app.app.test_client() as client:
        response = client.post(
            "/admin/approve-artisan/1",
            headers={"X-Admin-Key": "lifecycle-test-admin"},
        )

    assert response.status_code == 200
    assert response.get_json()["lifecycle_state"] == "APPROVED"
    row = lifecycle_endpoint_db.rows_by_id[1]
    assert row["lifecycle_state"] == "APPROVED"
    assert row["lifecycle_state"] != "ACTIVE"
    assert row["did"] == before["did"]
    assert row["algorand_wallet"] == before["algorand_wallet"]


@pytest.mark.parametrize("state", ["APPROVED", "WALLET_PROVISIONED", "DID_ISSUED", "ACTIVE", "SUSPENDED", "REVOKED", "REJECTED"])
def test_admin_approval_endpoint_rejects_non_applied_artisans(lifecycle_endpoint_db, state):
    lifecycle_endpoint_db.rows_by_id[1]["lifecycle_state"] = state

    with skillchain_app.app.test_client() as client:
        response = client.post(
            "/admin/approve-artisan/1",
            headers={"X-Admin-Key": "lifecycle-test-admin"},
        )

    assert response.status_code == 409
    assert lifecycle_endpoint_db.rows_by_id[1]["lifecycle_state"] == state


def _artwork_request(client, **extra_fields):
    fields = {
        "artisan_did": "did:skillchain:testnet:wallet:test-identity",
        "title": "Woven basket",
        "artwork": (BytesIO(b"image-bytes"), "basket.png"),
    }
    fields.update(extra_fields)
    return client.post("/add-artwork", data=fields, content_type="multipart/form-data")


def _artwork_downstream_must_not_run(monkeypatch):
    def fail(*_args, **_kwargs):
        pytest.fail("non-ACTIVE artisan reached artwork provisioning")

    for name in (
        "normalize_and_hash", "compute_binary_integrity_hash", "sign_credential_hash",
        "generate_hmac", "pin_with_retry", "get_algod_client", "sign_transaction",
        "wait_for_confirmation", "save_to_db",
    ):
        monkeypatch.setattr(skillchain_app, name, fail)


@pytest.mark.parametrize(
    "state",
    ["APPLIED", "APPROVED", "WALLET_PROVISIONED", "DID_ISSUED", "SUSPENDED", "REVOKED", "REJECTED"],
)
def test_artifact_registration_rejects_every_non_active_lifecycle_state(
    lifecycle_endpoint_db, monkeypatch, state
):
    lifecycle_endpoint_db.rows_by_id[1]["lifecycle_state"] = state
    _artwork_downstream_must_not_run(monkeypatch)

    with skillchain_app.app.test_client() as client:
        response = _artwork_request(client)

    assert response.status_code == 403
    assert response.get_json()["lifecycle_state"] == state
    assert lifecycle_endpoint_db.artwork_inserted is False


@pytest.mark.parametrize("override", [{"status": "active"}, {"lifecycle_state": "ACTIVE"}])
def test_artifact_registration_ignores_client_lifecycle_overrides(
    lifecycle_endpoint_db, monkeypatch, override
):
    lifecycle_endpoint_db.rows_by_id[1]["lifecycle_state"] = "APPLIED"
    _artwork_downstream_must_not_run(monkeypatch)

    with skillchain_app.app.test_client() as client:
        response = _artwork_request(client, **override)

    assert response.status_code == 403
    assert response.get_json()["lifecycle_state"] == "APPLIED"


def test_artifact_registration_allows_active_artisan_past_lifecycle_gate(
    lifecycle_endpoint_db, monkeypatch
):
    lifecycle_endpoint_db.rows_by_id[1]["lifecycle_state"] = "ACTIVE"
    monkeypatch.setattr(skillchain_app, "normalize_and_hash", lambda _image: "cert-hash")
    monkeypatch.setattr(skillchain_app, "compute_binary_integrity_hash", lambda _image: "integrity-hash")
    monkeypatch.setattr(skillchain_app, "sign_credential_hash", lambda *_args, **_kwargs: "signature")
    monkeypatch.setattr(skillchain_app, "generate_hmac", lambda _hash: "hmac")
    monkeypatch.setattr(skillchain_app, "pin_with_retry", lambda _metadata: "cid")
    monkeypatch.setattr(skillchain_app, "algo_txn_mod", SimpleNamespace(PaymentTxn=lambda **_kwargs: object()))
    monkeypatch.setattr(skillchain_app, "get_algod_client", lambda: SimpleNamespace(
        suggested_params=lambda: object(), send_transaction=lambda _txn: "tx-id"
    ))
    monkeypatch.setattr(skillchain_app, "sign_transaction", lambda _txn, _identity: object())
    monkeypatch.setattr(skillchain_app, "wait_for_confirmation", lambda *_args: None)
    monkeypatch.setattr(skillchain_app, "save_to_db", lambda *_args: None)

    with skillchain_app.app.test_client() as client:
        response = _artwork_request(client)

    assert response.status_code == 200
    assert lifecycle_endpoint_db.artwork_inserted is True
