"""
db_migrations.py — Idempotent schema migrations for SkillChain (PostgreSQL).

Called from app.py at startup (before first request).
Uses information_schema to check for existing columns so re-running on an
already-migrated DB is always safe.

Migration history
-----------------
  v1 (original): SQLite — address, did, institution, public_key, tx_id,
                           api_key, domain, registered_at
  v2:            adds per-institution wallet columns + revocation columns
  v3 (this file): migrated from SQLite to PostgreSQL (psycopg2 + DATABASE_URL)
"""

import logging

from db import get_db_connection

log = logging.getLogger(__name__)


def _column_exists(cur, table: str, column: str) -> bool:
    """Return True if the column already exists in the table."""
    cur.execute(
        """
        SELECT 1 FROM information_schema.columns
        WHERE table_name = %s AND column_name = %s
        """,
        (table, column),
    )
    return cur.fetchone() is not None


def _add_column_if_missing(cur, table: str, column: str, definition: str) -> None:
    """
    Add a column to a table only if it does not already exist.
    Safe to call multiple times — idempotent.
    """
    if not _column_exists(cur, table, column):
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        log.info("Migration: added column %s.%s", table, column)


def run_migrations() -> None:
    """
    Execute all pending schema migrations against PostgreSQL.

    Safe to call on every startup — already-applied changes are skipped.
    Never drops or renames existing columns.
    """
    conn = get_db_connection()
    cur  = conn.cursor()

    try:
        # ── did_registry ──────────────────────────────────────────────────────
        # SERIAL replaces INTEGER PRIMARY KEY AUTOINCREMENT.
        # address has a UNIQUE constraint so register_did can upsert via
        # INSERT ... ON CONFLICT (address) DO UPDATE SET ...
        cur.execute("""
            CREATE TABLE IF NOT EXISTS did_registry (
                id                  SERIAL PRIMARY KEY,
                institution_id      TEXT,
                address             TEXT,
                institution_address TEXT,
                did                 TEXT,
                institution         TEXT,
                public_key          TEXT,
                tx_id               TEXT,
                api_key             TEXT,
                domain              TEXT,
                registered_at       TEXT,
                private_key_enc     TEXT,
                key_nonce           TEXT,
                wallet_version      INTEGER DEFAULT 1,
                revoked             INTEGER DEFAULT 0,
                revoked_at          TEXT,
                revoked_reason      TEXT
            )
        """)

        # Add any columns that may be missing on existing databases
        for col, col_def in [
            ("institution_id",      "TEXT"),
            ("address",             "TEXT"),
            ("institution_address", "TEXT"),
            ("did",                 "TEXT"),
            ("institution",         "TEXT"),
            ("public_key",          "TEXT"),
            ("tx_id",               "TEXT"),
            ("api_key",             "TEXT"),
            ("domain",              "TEXT"),
            ("registered_at",       "TEXT"),
            ("private_key_enc",     "TEXT"),
            ("key_nonce",           "TEXT"),
            ("wallet_version",      "INTEGER DEFAULT 1"),
            ("revoked",             "INTEGER DEFAULT 0"),
            ("revoked_at",          "TEXT"),
            ("revoked_reason",      "TEXT"),
        ]:
            _add_column_if_missing(cur, "did_registry", col, col_def)

        # Ensure UNIQUE constraint on address (idempotent)
        cur.execute("""
            SELECT 1 FROM pg_indexes
            WHERE tablename = 'did_registry'
              AND indexname  = 'uq_did_registry_address'
        """)
        if not cur.fetchone():
            cur.execute(
                "ALTER TABLE did_registry "
                "ADD CONSTRAINT uq_did_registry_address UNIQUE (address)"
            )

        # Backfill legacy rows
        cur.execute("""
            UPDATE did_registry
            SET institution_id = 'LEGACY_SYSTEM',
                wallet_version  = 1
            WHERE institution_id IS NULL
        """)

        # ── pending_registrations ─────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pending_registrations (
                id           TEXT PRIMARY KEY,
                institution  TEXT NOT NULL,
                email        TEXT NOT NULL,
                domain       TEXT NOT NULL,
                verify_token TEXT NOT NULL,
                verified     INTEGER DEFAULT 0,
                approved     INTEGER DEFAULT 0,
                created_at   TEXT
            )
        """)

        # ── certificates ──────────────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                cert_hash   TEXT PRIMARY KEY,
                tx_id       TEXT NOT NULL,
                doc_type    TEXT,
                issued_at   TEXT,
                ipfs_cid    TEXT,
                cert_number TEXT,
                hmac_key    TEXT,
                hmac_value  TEXT,
                issued_to   TEXT
            )
        """)

        conn.commit()
        log.info("DB migrations completed successfully (PostgreSQL).")

    except Exception:
        conn.rollback()
        log.exception("DB migration failed — rolling back.")
        raise

    finally:
        cur.close()
        conn.close()