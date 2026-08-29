"""Focused tests for lifecycle-state migration of artisan rows."""

import db_migrations


class _MigrationCursor:
    """PostgreSQL migration double that executes the artisan lifecycle effects."""

    def __init__(self, rows, *, lifecycle_column_exists):
        self.rows = rows
        self.lifecycle_column_exists = lifecycle_column_exists
        self.lifecycle_not_null = False
        self.artisan_create_sql = None
        self._result = None

    def execute(self, query, params=None):
        normalized = " ".join(query.upper().split())
        self._result = None

        if "CREATE TABLE IF NOT EXISTS ARTISANS" in normalized:
            self.artisan_create_sql = query
        elif "SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS" in normalized:
            table, column = params
            exists = table != "artisans" or column != "lifecycle_state" or self.lifecycle_column_exists
            self._result = (1,) if exists else None
        elif "ALTER TABLE ARTISANS ADD COLUMN LIFECYCLE_STATE" in normalized:
            self.lifecycle_column_exists = True
            for row in self.rows:
                row.setdefault("lifecycle_state", "APPLIED")
        elif "SELECT COUNT(*) FROM ARTISANS WHERE ARTISAN_ID IS NULL" in normalized:
            self._result = (sum(row.get("artisan_id") is None for row in self.rows),)
        elif "SELECT ARTISAN_ID FROM ARTISANS GROUP BY ARTISAN_ID" in normalized:
            seen = set()
            duplicate = next((row["artisan_id"] for row in self.rows if row["artisan_id"] in seen or seen.add(row["artisan_id"])), None)
            self._result = (duplicate,) if duplicate is not None else None
        elif "UPDATE ARTISANS SET LIFECYCLE_STATE = 'APPROVED'" in normalized:
            for row in self.rows:
                if row.get("lifecycle_state") == "APPLIED" and row.get("status") == "approved":
                    row["lifecycle_state"] = "APPROVED"
        elif "UPDATE ARTISANS SET LIFECYCLE_STATE = 'REJECTED'" in normalized:
            for row in self.rows:
                if row.get("lifecycle_state") == "APPLIED" and row.get("status") == "rejected":
                    row["lifecycle_state"] = "REJECTED"
        elif "UPDATE ARTISANS SET LIFECYCLE_STATE = 'APPLIED' WHERE LIFECYCLE_STATE IS NULL" in normalized:
            for row in self.rows:
                if row.get("lifecycle_state") is None:
                    row["lifecycle_state"] = "APPLIED"
        elif "ALTER TABLE ARTISANS ALTER COLUMN LIFECYCLE_STATE SET NOT NULL" in normalized:
            self.lifecycle_not_null = True

    def fetchone(self):
        return self._result

    def close(self):
        pass


class _MigrationConnection:
    def __init__(self, cursor):
        self.cursor_obj = cursor
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


def _run_artisan_migration(monkeypatch, rows, *, lifecycle_column_exists=False):
    cursor = _MigrationCursor(rows, lifecycle_column_exists=lifecycle_column_exists)
    connection = _MigrationConnection(cursor)
    monkeypatch.setattr(db_migrations, "get_db_connection", lambda: connection)
    db_migrations.run_migrations()
    return cursor, connection


def test_fresh_artisan_schema_declares_applied_default_and_not_null(monkeypatch):
    cursor, connection = _run_artisan_migration(monkeypatch, [], lifecycle_column_exists=True)

    definition = " ".join(cursor.artisan_create_sql.upper().split())
    assert "LIFECYCLE_STATE TEXT NOT NULL DEFAULT 'APPLIED'" in definition
    assert cursor.lifecycle_not_null is True
    assert connection.committed is True


def test_lifecycle_migration_preserves_identity_fields_and_maps_legacy_statuses(monkeypatch):
    rows = [
        {
            "artisan_id": "artisan/approved", "did": "did:skillchain:approved",
            "algorand_wallet": "wallet-approved", "supabase_id": "supabase-approved",
            "status": "approved",
        },
        {
            "artisan_id": "artisan/rejected", "did": "did:skillchain:rejected",
            "algorand_wallet": "wallet-rejected", "supabase_id": "supabase-rejected",
            "status": "rejected",
        },
        {
            "artisan_id": "artisan/pending", "did": "did:skillchain:pending",
            "algorand_wallet": "wallet-pending", "supabase_id": "supabase-pending",
            "status": "pending",
        },
    ]
    identity_snapshot = [
        (row["artisan_id"], row["did"], row["algorand_wallet"], row["supabase_id"])
        for row in rows
    ]

    cursor, connection = _run_artisan_migration(monkeypatch, rows)

    assert [row["lifecycle_state"] for row in rows] == ["APPROVED", "REJECTED", "APPLIED"]
    assert "ACTIVE" not in [row["lifecycle_state"] for row in rows]
    assert [
        (row["artisan_id"], row["did"], row["algorand_wallet"], row["supabase_id"])
        for row in rows
    ] == identity_snapshot
    assert cursor.lifecycle_not_null is True
    assert connection.committed is True
