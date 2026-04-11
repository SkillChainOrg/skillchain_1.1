"""
db_migrations_w3c.py — Additive migration for W3C DID support.

Adds the did_documents table to cache resolved DID Documents.
Run this ONCE after deploying w3c_did_service.py.

This is a standalone migration script so it does not disrupt the existing
db_migrations.run_migrations() call in app.py. Simply call run_w3c_migrations()
from app.py startup (see integration instructions in INTEGRATION.md).
"""

import logging
from db import get_db_connection

log = logging.getLogger(__name__)


def run_w3c_migrations() -> None:
    """
    Idempotent: safe to call on every startup.
    Creates the did_documents cache table if it does not already exist.
    """
    conn = get_db_connection()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT pg_advisory_lock(987654321);")

        # ── did_documents ─────────────────────────────────────────────────────
        # Cache table for W3C DID Documents.
        # 'document' stores the full JSON blob as TEXT.
        # Queries hit this table first; did_registry is the source of truth.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS did_documents (
                id         SERIAL PRIMARY KEY,
                did        TEXT UNIQUE NOT NULL,
                document   TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_did_documents_did
            ON did_documents (did)
        """)

        # ── did_registry: add w3c_doc_generated flag ─────────────────────────
        # Tracks whether a W3C DID Document has been generated for each row.
        # Used by the backfill route (/admin/did/backfill) to find legacy rows.
        cur.execute("""
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'did_registry' AND column_name = 'w3c_doc_generated'
        """)
        if not cur.fetchone():
            cur.execute(
                "ALTER TABLE did_registry ADD COLUMN w3c_doc_generated INTEGER DEFAULT 0"
            )
            log.info("Migration: added did_registry.w3c_doc_generated column")

        conn.commit()
        log.info("W3C DID migrations completed.")

    except Exception:
        conn.rollback()
        log.exception("W3C DID migration failed — rolling back.")
        raise

    finally:
        try:
            cur.execute("SELECT pg_advisory_unlock(987654321);")
        except Exception:
            pass
        cur.close()
        conn.close()