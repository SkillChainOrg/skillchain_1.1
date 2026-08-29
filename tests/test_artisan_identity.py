"""Focused tests for stable, backend-generated SkillChain artisan identities."""

import inspect
import sqlite3
import uuid

import pytest
from flask import g

import app as skillchain_app


class _Cursor:
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, query, params=None):
        if params is None:
            return self._cursor.execute(query.replace("%s", "?"))
        return self._cursor.execute(query.replace("%s", "?"), params)

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def fetchone(self):
        row = self._cursor.fetchone()
        return dict(row) if row else None

    def close(self):
        self._cursor.close()


class _Connection:
    def __init__(self):
        self._connection = sqlite3.connect(":memory:")
        self._connection.row_factory = sqlite3.Row
        self._connection.execute(
            """
            CREATE TABLE artisans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artisan_id TEXT UNIQUE NOT NULL,
                did TEXT,
                name TEXT NOT NULL,
                craft_type TEXT,
                cluster TEXT,
                location TEXT,
                bio TEXT,
                years_of_experience INTEGER,
                profile_image TEXT,
                email TEXT,
                supabase_id TEXT UNIQUE,
                last_login TEXT,
                profile_completed BOOLEAN,
                status TEXT,
                lifecycle_state TEXT NOT NULL DEFAULT 'APPLIED',
                created_at TEXT,
                algorand_wallet TEXT
            )
            """
        )

    def cursor(self):
        return _Cursor(self._connection.cursor())

    def commit(self):
        self._connection.commit()

    def close(self):
        # The route owns a connection per request; this test database is shared
        # across requests so its rows can be asserted afterwards.
        pass


@pytest.fixture
def registration_db(monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(skillchain_app, "get_db_connection", lambda: connection)
    monkeypatch.setattr(skillchain_app, "dict_cursor", lambda conn: conn.cursor())
    return connection


def _register(monkeypatch, *, supabase_id, name, **profile):
    handler = inspect.unwrap(skillchain_app.register_artisan)
    payload = {"name": name, **profile}
    with skillchain_app.app.test_request_context("/register-artisan", method="POST", json=payload):
        g.supabase_id = supabase_id
        g.supabase_claims = {"email": f"{supabase_id}@example.test"}
        response, status = handler()
    return response.get_json(), status


def test_artisan_id_is_random_uuid_with_unchanged_prefix():
    first = skillchain_app._generate_artisan_id()
    second = skillchain_app._generate_artisan_id()

    assert first != second
    assert first.startswith("artisan/")
    assert second.startswith("artisan/")
    assert inspect.signature(skillchain_app._generate_artisan_id).parameters == {}
    assert str(uuid.UUID(first.removeprefix("artisan/"))) == first.removeprefix("artisan/")


def test_identically_named_artisans_receive_distinct_ids_and_api_field(registration_db, monkeypatch):
    first, first_status = _register(monkeypatch, supabase_id="user-1", name="Asha Patel")
    second, second_status = _register(monkeypatch, supabase_id="user-2", name="Asha Patel")

    assert first_status == second_status == 201
    assert first["artisan_id"] != second["artisan_id"]
    assert first["artisan_id"].startswith("artisan/")
    assert first["lifecycle_state"] == second["lifecycle_state"] == "APPLIED"
    assert "artisan_id" in second


def test_name_changes_and_registration_retry_preserve_existing_identity(registration_db, monkeypatch):
    created, status = _register(monkeypatch, supabase_id="user-1", name="Asha Patel")
    retried, retry_status = _register(monkeypatch, supabase_id="user-1", name="Asha Renamed")

    assert status == 201
    assert retry_status == 200
    assert retried["existing"] is True
    assert retried["artisan_id"] == created["artisan_id"]
    assert registration_db._connection.execute("SELECT COUNT(*) FROM artisans").fetchone()[0] == 1


def test_existing_artisan_id_is_preserved_and_registration_creates_no_did_or_wallet(registration_db, monkeypatch):
    registration_db._connection.execute(
        """
        INSERT INTO artisans (artisan_id, name, supabase_id, status)
        VALUES (?, ?, ?, ?)
        """,
        ("artisan/legacy-identity", "Original Name", "legacy-user", "pending"),
    )
    registration_db.commit()

    response, status = _register(monkeypatch, supabase_id="legacy-user", name="Changed Name")

    assert status == 200
    assert response["artisan_id"] == "artisan/legacy-identity"
    row = registration_db._connection.execute(
        "SELECT did, algorand_wallet FROM artisans WHERE supabase_id = ?", ("legacy-user",)
    ).fetchone()
    assert row["did"] is None
    assert row["algorand_wallet"] is None


def test_artisan_id_database_constraints_enforce_uniqueness_and_non_null(registration_db):
    with pytest.raises(sqlite3.IntegrityError):
        registration_db._connection.execute(
            "INSERT INTO artisans (artisan_id, name, supabase_id) VALUES (?, ?, ?)",
            (None, "No Identity", "null-user"),
        )

    registration_db._connection.execute(
        "INSERT INTO artisans (artisan_id, name, supabase_id) VALUES (?, ?, ?)",
        ("artisan/fixed-id", "First", "first-user"),
    )
    with pytest.raises(sqlite3.IntegrityError):
        registration_db._connection.execute(
            "INSERT INTO artisans (artisan_id, name, supabase_id) VALUES (?, ?, ?)",
            ("artisan/fixed-id", "Second", "second-user"),
        )
