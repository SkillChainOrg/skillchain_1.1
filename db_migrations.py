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
    conn.execute("""
    CREATE TABLE IF NOT EXISTS did_registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    institution_id TEXT,
    institution_address TEXT,
    private_key_enc TEXT,
    key_nonce TEXT,
    wallet_version INTEGER DEFAULT 1
)
""")
    try:
        # ── did_registry v2 columns ──────────────────────────────────────────────
    
        # 16-char hex institution identifier (derived from institution name via SHA-256).
        # 'LEGACY_SYSTEM' for rows issued before per-institution wallets were introduced.
        _add_column_if_missing(conn, "did_registry", "institution_id",   "TEXT")
        _add_column_if_missing(conn, "did_registry", "address", "TEXT")

        # The institution's own Algorand address (distinct from the system wallet address).
        # NULL for legacy rows.
        _add_column_if_missing(conn, "did_registry", "institution_address", "TEXT")

        # AES-256-GCM ciphertext (base64).  Used ONLY when VAULT_ENABLED=false.
        # NULL when VAULT_ENABLED=true (key lives in Vault, not here).
        _add_column_if_missing(conn, "did_registry", "private_key_enc",  "TEXT")

        # AES-256-GCM nonce (base64).  Paired with private_key_enc.
        _add_column_if_missing(conn, "did_registry", "key_nonce",        "TEXT")

        # 1 = legacy shared system wallet (wallet_version < 2)
        # 2 = per-institution dedicated wallet
        _add_column_if_missing(conn, "did_registry", "wallet_version",   "INTEGER DEFAULT 1")

        # ── Revocation columns ───────────────────────────────────────────────────
        _add_column_if_missing(conn, "did_registry", "revoked",          "INTEGER DEFAULT 0")
        _add_column_if_missing(conn, "did_registry", "revoked_at",       "TEXT")
        _add_column_if_missing(conn, "did_registry", "revoked_reason",   "TEXT")

        conn.commit()

        # ── Legacy row backfill ──────────────────────────────────────────────────
        # Mark all rows created before this migration as wallet_version=1 / LEGACY_SYSTEM.
        conn.execute("""
            UPDATE did_registry
            SET institution_id   = 'LEGACY_SYSTEM',
                wallet_version   = 1
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
