"""
Idempotent schema migrations for SkillChain SQLite database.

Called from app.py at startup (before first request).
Uses explicit PRAGMA table inspection so migrations are deterministic and
safe to rerun on every startup.
"""

import sqlite3
import logging
import os

log = logging.getLogger(__name__)

DB_PATH = os.getenv("DB_PATH", "skillchain.db")


def _get_existing_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {row[1] for row in rows}


def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    """Add a column only when it is absent."""
    if column in _get_existing_columns(conn, table):
        return
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    except Exception:
        pass  # ignore duplicate column error
    log.info("Migration: added column %s.%s", table, column)


def run_migrations() -> None:
    """
    Execute all pending schema migrations.

    Safe to call on every startup — already-applied changes are skipped.
    Never drops or renames existing columns.
    """
    conn = sqlite3.connect(DB_PATH)

    # ✅ Base table (complete schema for fresh DBs)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS did_registry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        institution_id TEXT,
        address TEXT,
        institution_address TEXT,
        did TEXT,
        private_key_enc TEXT,
        key_nonce TEXT,
        wallet_version INTEGER DEFAULT 1,
        revoked INTEGER DEFAULT 0,
        revoked_at TEXT,
        revoked_reason TEXT
    )
    """)

    try:
        for col, col_type in [
            ("institution_id", "TEXT"),
            ("address", "TEXT"),
            ("institution_address", "TEXT"),
            ("did", "TEXT"),
            ("private_key_enc", "TEXT"),
            ("key_nonce", "TEXT"),
            ("wallet_version", "INTEGER DEFAULT 1"),
            ("revoked", "INTEGER DEFAULT 0"),
            ("revoked_at", "TEXT"),
            ("revoked_reason", "TEXT"),
        ]:
            _add_column_if_missing(conn, "did_registry", col, col_type)

        conn.commit()

        # ── Legacy row backfill ──────────────────────────────────────────────
        conn.execute("""
            UPDATE did_registry
            SET institution_id = 'LEGACY_SYSTEM',
                wallet_version = 1
            WHERE institution_id IS NULL
        """)
        conn.commit()

        log.info("DB migrations completed successfully.")

    except Exception:
        conn.rollback()
        log.exception("DB migration failed — rolling back.")
        raise
    finally:
        conn.close()
