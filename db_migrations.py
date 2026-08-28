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


def _ensure_artisan_id_constraint(cur) -> None:
    """Safely enforce artisan_id constraints without rewriting legacy rows."""
    cur.execute("SELECT COUNT(*) FROM artisans WHERE artisan_id IS NULL")
    null_count = cur.fetchone()[0]
    if null_count:
        raise RuntimeError(
            f"Cannot enforce artisans.artisan_id NOT NULL: {null_count} NULL value(s) exist"
        )

    cur.execute(
        """
        SELECT artisan_id
        FROM artisans
        GROUP BY artisan_id
        HAVING COUNT(*) > 1
        LIMIT 1
        """
    )
    duplicate = cur.fetchone()
    if duplicate:
        raise RuntimeError(
            "Cannot enforce unique artisans.artisan_id: duplicate value exists "
            f"({duplicate[0]!r})"
        )

    cur.execute("ALTER TABLE artisans ALTER COLUMN artisan_id SET NOT NULL")


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
                artisan_id        TEXT UNIQUE NOT NULL,
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
            # Supabase auth linkage. Authentication (Google OAuth + phone) happens
            # in the frontend via Supabase; the backend verifies the Supabase JWT
            # and links the user to this row via supabase_id (the JWT `sub` claim).
            ("supabase_id",       "TEXT"),
            ("email",             "TEXT"),
            ("last_login",        "TEXT"),
            ("profile_completed", "BOOLEAN DEFAULT FALSE"),
            ("bio",                 "TEXT"),
            ("years_of_experience", "INTEGER"),
            ("profile_image",       "TEXT"),
        ]:
            _add_column_if_missing(cur, "artisans", col, col_def)

        # Validate legacy rows before tightening the existing table. The
        # surrounding migration transaction rolls back on invalid data.
        _ensure_artisan_id_constraint(cur)

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

        # Supabase user id is the lookup key used by the JWT auth layer
        # (auth_supabase.load_artisan_by_supabase_id). Unique so one Supabase
        # account maps to exactly one artisan profile.
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uidx_artisans_supabase_id
            ON artisans (supabase_id)
            WHERE supabase_id IS NOT NULL
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_artworks_artisan_did
            ON artworks (artisan_did)
        """)

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uidx_artworks_cert_hash
            ON artworks (cert_hash)
        """)

        # ── acquisitions (commerce v1) ───────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS acquisitions (
                id                 SERIAL PRIMARY KEY,
                acquisition_id     TEXT UNIQUE,
                artwork_id         INTEGER NOT NULL,
                artist_did         TEXT,
                buyer_name         TEXT,
                buyer_email        TEXT,
                collector_reference_id TEXT,
                amount             INTEGER,
                currency           TEXT,
                razorpay_order_id  TEXT,
                razorpay_payment_id TEXT,
                payment_status     TEXT,
                settlement_mode    TEXT DEFAULT 'domestic_upi',
                timestamp          TEXT
            )
        """)

        for col, col_def in [
            ("acquisition_id",      "TEXT"),
            ("artwork_id",          "INTEGER"),
            ("artist_did",          "TEXT"),
            ("buyer_name",          "TEXT"),
            ("buyer_email",         "TEXT"),
            ("collector_reference_id", "TEXT"),
            ("amount",              "INTEGER"),
            ("currency",            "TEXT"),
            ("razorpay_order_id",   "TEXT"),
            ("razorpay_payment_id", "TEXT"),
            ("payment_status",      "TEXT"),
            ("settlement_mode",     "TEXT DEFAULT 'domestic_upi'"),
            ("challenge_nonce",     "TEXT"),
            ("algorand_tx_id",      "TEXT"),
            ("algorand_group_id",   "TEXT"),
            ("wallet_address",      "TEXT"),
            ("algorand_app_id",     "BIGINT"),
            ("timestamp",           "TEXT"),
        ]:
            _add_column_if_missing(cur, "acquisitions", col, col_def)

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uidx_acquisitions_acquisition_id
            ON acquisitions (acquisition_id)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_acquisitions_artwork_id
            ON acquisitions (artwork_id)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_acquisitions_order_id
            ON acquisitions (razorpay_order_id)
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_acquisitions_collector_ref
            ON acquisitions (collector_reference_id)
        """)

        # ── provenance events (append-only) ──────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS artwork_provenance_events (
                id         SERIAL PRIMARY KEY,
                artwork_id INTEGER NOT NULL,
                provenance_event_type TEXT,
                event_type TEXT NOT NULL,
                event_json TEXT NOT NULL,
                created_at TEXT
            )
        """)
        for col, col_def in [
            ("artwork_id", "INTEGER"),
            ("provenance_event_type", "TEXT"),
            ("event_type", "TEXT"),
            ("event_json", "TEXT"),
            ("created_at", "TEXT"),
        ]:
            _add_column_if_missing(cur, "artwork_provenance_events", col, col_def)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_artwork_prov_artwork_id
            ON artwork_provenance_events (artwork_id)
        """)

        # ── ownership metadata (current owner) ───────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS artwork_ownership (
                artwork_id     INTEGER PRIMARY KEY,
                acquisition_id TEXT,
                owner_name     TEXT,
                owner_email    TEXT,
                collector_reference_id TEXT,
                updated_at     TEXT
            )
        """)
        for col, col_def in [
            ("acquisition_id", "TEXT"),
            ("owner_name",     "TEXT"),
            ("owner_email",    "TEXT"),
            ("owner_wallet",   "TEXT"),
            ("collector_reference_id", "TEXT"),
            ("updated_at",     "TEXT"),
        ]:
            _add_column_if_missing(cur, "artwork_ownership", col, col_def)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS x402_payment_challenges (
                id SERIAL PRIMARY KEY,
                nonce TEXT UNIQUE,
                artwork_id INTEGER NOT NULL,
                acquisition_id TEXT,
                collector_name TEXT,
                collector_email TEXT,
                amount_microalgos BIGINT NOT NULL,
                receiver TEXT NOT NULL,
                app_id BIGINT NOT NULL,
                network TEXT NOT NULL,
                wallet_address TEXT,
                tx_id TEXT,
                group_id TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL
            )
        """)
        for col, col_def in [
            ("nonce", "TEXT"),
            ("artwork_id", "INTEGER"),
            ("acquisition_id", "TEXT"),
            ("collector_name", "TEXT"),
            ("collector_email", "TEXT"),
            ("amount_microalgos", "BIGINT"),
            ("receiver", "TEXT"),
            ("app_id", "BIGINT"),
            ("network", "TEXT"),
            ("wallet_address", "TEXT"),
            ("tx_id", "TEXT"),
            ("group_id", "TEXT"),
            ("status", "TEXT DEFAULT 'pending'"),
            ("expires_at", "TEXT"),
            ("used_at", "TEXT"),
            ("created_at", "TEXT"),
        ]:
            _add_column_if_missing(cur, "x402_payment_challenges", col, col_def)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uidx_x402_payment_challenges_nonce
            ON x402_payment_challenges (nonce)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_x402_payment_challenges_artwork_id
            ON x402_payment_challenges (artwork_id)
        """)

        # ── collectors (minimal provenance metadata; no accounts) ────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS collectors (
                id SERIAL PRIMARY KEY,
                collector_reference_id TEXT UNIQUE,
                collector_name  TEXT,
                collector_email TEXT,
                created_at      TEXT
            )
        """)
        for col, col_def in [
            ("collector_reference_id", "TEXT"),
            ("collector_name", "TEXT"),
            ("collector_email", "TEXT"),
            ("created_at", "TEXT"),
        ]:
            _add_column_if_missing(cur, "collectors", col, col_def)

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uidx_collectors_ref
            ON collectors (collector_reference_id)
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
