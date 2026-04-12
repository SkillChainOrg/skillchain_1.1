"""
db_migrations.py — Idempotent schema migrations for SkillChain (PostgreSQL).

SCHEMA CHANGES (this revision):
  1. certificates.hmac_key column dropped.
     HMAC keys are now derived at runtime from HMAC_MASTER_KEY env var.
     They must never be stored alongside the HMAC value they protect.
     Existing rows retain the column value until the column is dropped by a
     DBA (safe — the column is no longer read or written by the application).

  2. certificates.issued_to semantics changed.
     Was: SHA-256(name.strip().lower()) — a name hash with collision risk.
     Now: identity_did (did:skillchain:identity:...)  — a unique, unforgeable DID.
     The column type is unchanged (TEXT); only the content semantics differ.
     Existing rows with old name-hashes remain readable but will not match
     DID-based verification — this is intentional (they predate identity binding).
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
    cur  = conn.cursor()

    try:
        # Prevent race condition across multiple workers
        cur.execute("SELECT pg_advisory_lock(123456789);")

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
        # hmac_key is intentionally absent from CREATE TABLE.
        # issued_to stores identity_did (not hash(name)) for new rows.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                cert_hash   TEXT PRIMARY KEY,
                tx_id       TEXT NOT NULL,
                doc_type    TEXT,
                issued_at   TEXT,
                ipfs_cid    TEXT,
                cert_number TEXT,
                issued_to   TEXT
                -- hmac_value intentionally absent: recomputed at verify time,
                -- never stored (see security note in algorand_service.py)
            )
        """)

        # FIX A: Actively DROP hmac_value if it exists on old deployments.
        # Storing HMAC output alongside cert_hash gives attackers a
        # known-plaintext corpus. This migration is safe — the column is
        # no longer written or read; DROP removes the security liability.
        for stale_col in ("hmac_key", "hmac_value"):
            if _column_exists(cur, "certificates", stale_col):
                cur.execute(
                    f"ALTER TABLE certificates DROP COLUMN IF EXISTS {stale_col}"
                )
                log.info(
                    "Security migration: dropped certificates.%s "
                    "(HMAC values must not be stored alongside protected data).",
                    stale_col,
                )

        # ── identity_anchors ─────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS identity_anchors (
                id             SERIAL PRIMARY KEY,
                identity_did   TEXT UNIQUE NOT NULL,
                digilocker_id  TEXT UNIQUE NOT NULL,
                name_hash      TEXT NOT NULL,
                bound_at       TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_identity_anchors_digilocker_id
            ON identity_anchors (digilocker_id)
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_identity_anchors_identity_did
            ON identity_anchors (identity_did)
        """)

        conn.commit()
        log.info("DB migrations completed successfully (PostgreSQL).")

    except Exception:
        conn.rollback()
        log.exception("DB migration failed — rolling back.")
        raise

    finally:
        try:
            cur.execute("SELECT pg_advisory_unlock(123456789);")
        except Exception:
            pass

        cur.close()
        conn.close()