"""
db_migrations.py — Idempotent schema migrations for SkillChain (PostgreSQL)
"""

import logging
from db import get_db_connection

log = logging.getLogger(__name__)


def _column_exists(cur, table: str, column: str) -> bool:
    cur.execute(
        """
        SELECT 1 FROM information_schema.columns
        WHERE table_name = %s AND column_name = %s
        """,
        (table, column),
    )
    return cur.fetchone() is not None


def _add_column_if_missing(cur, table: str, column: str, definition: str) -> None:
    if not _column_exists(cur, table, column):
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        log.info("Migration: added column %s.%s", table, column)


def run_migrations() -> None:
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # ── did_registry ─────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS did_registry (
                id                  SERIAL PRIMARY KEY,
                institution_id      TEXT,
                address             TEXT UNIQUE,
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

        # Safe column additions
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

        # Backfill legacy rows
        cur.execute("""
            UPDATE did_registry
            SET institution_id = 'LEGACY_SYSTEM',
                wallet_version = 1
            WHERE institution_id IS NULL
        """)

        # ── pending_registrations ────────────────────────────
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

        # ── certificates ─────────────────────────────────────
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