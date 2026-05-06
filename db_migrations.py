"""
db_migrations.py — Idempotent schema migrations for SkillChain (PostgreSQL).

SCHEMA CHANGES (this revision):
  1. certificates.hmac_key column dropped.
  2. certificates.issued_to semantics changed to identity_did.
  3. Unique indexes added for idempotency (case-insensitive) on
     pending_registrations and did_registry (Fix 1).
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
            ("vault_key_id",        "TEXT"),   # Vault path segment; NULL when AES-GCM mode
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
        cur.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                cert_hash   TEXT PRIMARY KEY,
                tx_id       TEXT NOT NULL,
                doc_type    TEXT,
                issued_at   TEXT,
                ipfs_cid    TEXT,
                cert_number TEXT,
                issued_to   TEXT
            )
        """)

        for stale_col in ("hmac_key", "hmac_value"):
            if _column_exists(cur, "certificates", stale_col):
                cur.execute(
                    f"ALTER TABLE certificates DROP COLUMN IF EXISTS {stale_col}"
                )
                log.info(
                    "Security migration: dropped certificates.%s", stale_col,
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

        # ── Fix 1: Unique indexes for idempotency (case-insensitive) ─────────
        # Prevents duplicate institutions from being registered under different
        # capitalisation or minor variations of the same name / email / domain.

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uidx_pending_email
            ON pending_registrations (LOWER(email))
        """)

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uidx_pending_domain
            ON pending_registrations (LOWER(domain))
        """)

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uidx_pending_institution
            ON pending_registrations (LOWER(institution))
        """)

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uidx_did_reg_institution
            ON did_registry (LOWER(institution))
        """)

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uidx_did_reg_domain
            ON did_registry (LOWER(domain))
        """)

        # ── artisans ──────────────────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS artisans (
                id                SERIAL PRIMARY KEY,
                artisan_id        TEXT UNIQUE,
                did               TEXT,
                name              TEXT NOT NULL,
                craft_type        TEXT,
                cluster           TEXT,
                location          TEXT,
                algorand_wallet   TEXT,
                ed25519_pubkey    TEXT,
                enc_private_key   TEXT,
                key_nonce         TEXT,
                vault_key_version TEXT,
                status            TEXT DEFAULT 'pending',
                approved_by       TEXT,
                approved_at       TEXT,
                created_at        TEXT
            )
        """)

        for col, col_def in [
            ("artisan_id",        "TEXT"),
            ("did",               "TEXT"),
            ("craft_type",        "TEXT"),
            ("cluster",           "TEXT"),
            ("location",          "TEXT"),
            ("algorand_wallet",   "TEXT"),
            ("ed25519_pubkey",    "TEXT"),
            ("enc_private_key",   "TEXT"),
            ("key_nonce",         "TEXT"),
            ("vault_key_version", "TEXT"),
            ("status",            "TEXT DEFAULT 'pending'"),
            ("approved_by",       "TEXT"),
            ("approved_at",       "TEXT"),
            ("created_at",        "TEXT"),
        ]:
            _add_column_if_missing(cur, "artisans", col, col_def)

        # ── artworks ──────────────────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS artworks (
                id          SERIAL PRIMARY KEY,
                artisan_did TEXT NOT NULL,
                title       TEXT,
                description TEXT,
                materials   TEXT,
                cert_hash   TEXT UNIQUE,
                signature   TEXT,
                ipfs_cid    TEXT,
                tx_id       TEXT,
                status      TEXT DEFAULT 'pending',
                created_at  TEXT
            )
        """)

        for col, col_def in [
            ("artisan_did",  "TEXT NOT NULL"),
            ("title",        "TEXT"),
            ("description",  "TEXT"),
            ("materials",    "TEXT"),
            ("cert_hash",    "TEXT"),
            ("signature",    "TEXT"),
            ("ipfs_cid",     "TEXT"),
            ("tx_id",        "TEXT"),
            ("status",       "TEXT DEFAULT 'pending'"),
            ("created_at",   "TEXT"),
        ]:
            _add_column_if_missing(cur, "artworks", col, col_def)

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uidx_artisans_artisan_id
            ON artisans (artisan_id)
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_artworks_artisan_did
            ON artworks (artisan_did)
        """)

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uidx_artworks_cert_hash
            ON artworks (cert_hash)
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