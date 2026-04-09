"""
Idempotent schema migrations for SkillChain SQLite database.

Called from app.py at startup (before first request).
Uses explicit PRAGMA table inspection so migrations are deterministic and
safe to rerun on every startup.

FIXED:
  - did_registry was missing: institution, public_key, tx_id, api_key,
    domain, registered_at — causing register_did() to crash on INSERT.
  - certificates table now stores cert_number, hmac_key, hmac_value,
    issued_to to support the verification flow.
"""

import sqlite3
import logging
import os

log = logging.getLogger(__name__)

DB_PATH = os.getenv("DB_PATH", "skillchain.db")


def _get_existing_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {row[1] for row in rows}


def _add_column_if_missing(
    conn: sqlite3.Connection, table: str, column: str, definition: str
) -> None:
    """Add a column only when it is absent."""
    if column in _get_existing_columns(conn, table):
        return
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        log.info("Migration: added column %s.%s", table, column)
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            pass
        else:
            raise


def run_migrations() -> None:
    """
    Execute all pending schema migrations.

    Safe to call on every startup — already-applied changes are skipped.
    Never drops or renames existing columns.
    """
    conn = sqlite3.connect(DB_PATH)

    # ── did_registry: full schema including previously-missing cols ──────────
    #
    # IMPORTANT: init_did_db() in did_service.py also issues a CREATE TABLE IF
    # NOT EXISTS for this table.  Because db_migrations runs first (app.py
    # startup order), this CREATE TABLE below is the authoritative definition.
    # init_did_db()'s CREATE is a no-op (table already exists) so all columns
    # must live here.
    conn.execute("""
    CREATE TABLE IF NOT EXISTS did_registry (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        address          TEXT,
        institution_address TEXT,
        institution_id   TEXT,
        institution      TEXT,
        did              TEXT,
        public_key       TEXT,
        tx_id            TEXT,
        api_key          TEXT,
        domain           TEXT,
        registered_at    TEXT,
        private_key_enc  TEXT,
        key_nonce        TEXT,
        wallet_version   INTEGER DEFAULT 1,
        revoked          INTEGER DEFAULT 0,
        revoked_at       TEXT,
        revoked_reason   TEXT
    )
    """)

    # Add any column that may be missing on an existing (pre-migration) DB
    did_registry_cols = [
        ("address",             "TEXT"),
        ("institution_address", "TEXT"),
        ("institution_id",      "TEXT"),
        ("institution",         "TEXT"),
        ("did",                 "TEXT"),
        ("public_key",          "TEXT"),
        ("tx_id",               "TEXT DEFAULT 'pending'"),
        ("api_key",             "TEXT"),
        ("domain",              "TEXT"),
        ("registered_at",       "TEXT"),
        ("private_key_enc",     "TEXT"),
        ("key_nonce",           "TEXT"),
        ("wallet_version",      "INTEGER DEFAULT 1"),
        ("revoked",             "INTEGER DEFAULT 0"),
        ("revoked_at",          "TEXT"),
        ("revoked_reason",      "TEXT"),
    ]
    for col, col_def in did_registry_cols:
        _add_column_if_missing(conn, "did_registry", col, col_def)

    # ── pending_registrations ────────────────────────────────────────────────
    conn.execute("""
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

    # ── certificates: extended with cert_number, HMAC, issued_to ────────────
    #
    # cert_number  : institution-assigned roll/certificate number (lookup key
    #               for the DigiLocker verification path)
    # hmac_key     : per-certificate secret used to re-derive hmac_value
    #               (stored in DB, NOT in IPFS)
    # hmac_value   : HMAC-SHA256(hmac_key, cert_hash) stored in IPFS for
    #               tamper-evidence; re-computed at verify time
    # issued_to    : hashed name of the certificate holder (SHA-256 of
    #               name.strip().lower()) — allows identity verification
    #               without storing PII
    conn.execute("""
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

    cert_cols = [
        ("ipfs_cid",   "TEXT"),
        ("cert_number","TEXT"),
        ("hmac_key",   "TEXT"),
        ("hmac_value", "TEXT"),
        ("issued_to",  "TEXT"),
    ]
    for col, col_def in cert_cols:
        _add_column_if_missing(conn, "certificates", col, col_def)

    # ── Legacy row backfill ──────────────────────────────────────────────────
    conn.execute("""
        UPDATE did_registry
        SET institution_id = 'LEGACY_SYSTEM',
            wallet_version = 1
        WHERE institution_id IS NULL
    """)

    conn.commit()
    conn.close()
    log.info("DB migrations completed successfully.")