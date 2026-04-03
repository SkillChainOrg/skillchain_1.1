"""
db_migrations.py — Idempotent schema migrations for SkillChain SQLite database.

Called from app.py at startup (before first request).
Uses the "ALTER TABLE IF NOT ADDED" pattern via try/except on OperationalError
so re-running on an already-migrated DB is always safe.

Migration history
-----------------
  v1 (original): address, did, institution, public_key, tx_id, api_key, domain, registered_at
  v2 (this file): adds per-institution wallet columns + revocation columns
"""

import sqlite3
import logging
import os

log = logging.getLogger(__name__)

DB_PATH = os.getenv("DB_PATH", "skillchain.db")


def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    """
    Add a column to a table only if it does not already exist.
    Safe to call multiple times — idempotent.
    """
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        log.info("Migration: added column %s.%s", table, column)
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            pass  # column already exists — nothing to do
        else:
            raise  # unexpected error — re-raise


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
        # 🔥 FORCE FIXES (handles broken existing DBs reliably)
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
            try:
                conn.execute(f"ALTER TABLE did_registry ADD COLUMN {col} {col_type}")
            except Exception:
                # Column already exists → ignore
                pass

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
