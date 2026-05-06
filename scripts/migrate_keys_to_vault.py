"""
scripts/migrate_keys_to_vault.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
One-time migration: move per-institution private keys from AES-GCM encrypted
columns in did_registry to HashiCorp Vault KV v2.

Safety guarantees
-----------------
* Idempotent — if a key already exists in Vault for an institution, that row
  is SKIPPED (no overwrite, no failure).
* Per-row failure — a Vault or DB error on one institution is logged and the
  script continues to the next.  The overall failure count is reported at the
  end.
* Memory safety — decrypted key bytes are deleted with ``del`` immediately
  after the Vault write, inside a ``finally`` block.
* No data loss — the DB columns are only NULLed out AFTER a confirmed Vault
  write.  If the NULL update fails, the encrypted blob is still in the DB and
  can be retried.

Usage
-----
    python scripts/migrate_keys_to_vault.py            # live run
    python scripts/migrate_keys_to_vault.py --dry-run  # print what would change

Required environment variables
-------------------------------
    VAULT_ENABLED=true
    VAULT_URL          e.g. https://vault.example.com
    VAULT_TOKEN        root or AppRole token
    DATABASE_URL       postgresql://...
    KEY_ENCRYPTION_KEY 64-char hex (to decrypt existing AES-GCM blobs)
"""

import os
import sys
import logging
import argparse

# ── Allow importing project modules from the repo root ───────────────────────
_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_SCRIPT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from dotenv import load_dotenv
load_dotenv(os.path.join(_PROJECT_DIR, ".env"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("migrate_keys_to_vault")


def _validate_environment() -> None:
    """Abort early if the environment is not configured for a Vault migration."""
    if os.getenv("VAULT_ENABLED", "false").lower() != "true":
        log.error("VAULT_ENABLED is not 'true'. Set VAULT_ENABLED=true before running this script.")
        sys.exit(1)

    for var in ("VAULT_URL", "VAULT_TOKEN", "DATABASE_URL", "KEY_ENCRYPTION_KEY"):
        if not os.getenv(var):
            log.error("Required environment variable %s is not set.", var)
            sys.exit(1)


def _vault_key_exists(institution_id: str) -> bool:
    """
    Return True if Vault already holds a key for this institution.
    Suppresses KeyError (not found) and propagates other exceptions.
    """
    from vault_client import read_key
    try:
        read_key(institution_id)
        return True
    except KeyError:
        return False


def main(dry_run: bool = False) -> None:
    _validate_environment()

    from db import get_db_connection, dict_cursor
    from key_vault import decrypt_key
    from vault_client import write_key

    log.info("=== SkillChain Key Migration: AES-GCM → Vault ===")
    if dry_run:
        log.info("DRY-RUN mode — no writes will be performed.")

    # ── Fetch all rows that still have encrypted keys in DB ──────────────────
    conn = get_db_connection()
    cur  = dict_cursor(conn)
    try:
        cur.execute(
            """
            SELECT institution_id, private_key_enc, key_nonce
            FROM did_registry
            WHERE private_key_enc IS NOT NULL
              AND key_nonce       IS NOT NULL
            ORDER BY institution_id
            """
        )
        rows = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    if not rows:
        log.info("No rows with private_key_enc found. Nothing to migrate.")
        return

    log.info("Found %d institution(s) with AES-GCM encrypted keys.", len(rows))

    migrated = 0
    skipped  = 0
    failed   = []

    for row in rows:
        institution_id   = row["institution_id"]
        private_key_enc  = row["private_key_enc"]
        key_nonce        = row["key_nonce"]

        log.info("Processing institution_id=%s …", institution_id)

        # ── Idempotency check ─────────────────────────────────────────────────
        try:
            already_in_vault = _vault_key_exists(institution_id)
        except Exception as exc:
            log.error(
                "  [SKIP] Vault existence check failed for %s: %s",
                institution_id, exc,
            )
            failed.append((institution_id, f"vault-check: {exc}"))
            continue

        if already_in_vault:
            log.info(
                "  [SKIP] Key already exists in Vault for institution_id=%s — not overwriting.",
                institution_id,
            )
            skipped += 1
            continue

        # ── Decrypt AES-GCM key ───────────────────────────────────────────────
        key_bytes = None
        try:
            key_bytes = decrypt_key(private_key_enc, key_nonce)
        except Exception as exc:
            log.error(
                "  [FAIL] AES-GCM decryption failed for institution_id=%s: %s",
                institution_id, exc,
            )
            failed.append((institution_id, f"decrypt: {exc}"))
            continue

        # ── Write to Vault ────────────────────────────────────────────────────
        try:
            if dry_run:
                log.info(
                    "  [DRY] Would write %d-byte key to Vault for institution_id=%s.",
                    len(key_bytes), institution_id,
                )
            else:
                write_key(institution_id, key_bytes)
                log.info(
                    "  [OK]  Vault write succeeded for institution_id=%s.", institution_id
                )
        except Exception as exc:
            log.error(
                "  [FAIL] Vault write failed for institution_id=%s: %s",
                institution_id, exc,
            )
            failed.append((institution_id, f"vault-write: {exc}"))
            continue
        finally:
            # Delete decrypted bytes IMMEDIATELY regardless of success/failure.
            if key_bytes is not None:
                del key_bytes

        if dry_run:
            skipped += 1
            continue

        # ── NULL out DB columns (only after confirmed Vault write) ────────────
        try:
            conn2 = get_db_connection()
            cur2  = conn2.cursor()
            try:
                cur2.execute(
                    """
                    UPDATE did_registry
                    SET private_key_enc = NULL,
                        key_nonce       = NULL,
                        vault_key_id    = %s
                    WHERE institution_id = %s
                    """,
                    (institution_id, institution_id),
                )
                conn2.commit()
                log.info(
                    "  [OK]  DB columns cleared and vault_key_id set for institution_id=%s.",
                    institution_id,
                )
            finally:
                cur2.close()
                conn2.close()
        except Exception as exc:
            log.error(
                "  [FAIL] DB update failed for institution_id=%s (key IS in Vault): %s",
                institution_id, exc,
            )
            failed.append((institution_id, f"db-nullout: {exc}"))
            continue

        migrated += 1

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print(f"Migration {'(DRY RUN) ' if dry_run else ''}summary")
    print("=" * 60)
    print(f"  Total processed : {len(rows)}")
    print(f"  Migrated        : {migrated}")
    print(f"  Skipped         : {skipped}  (already in Vault or dry-run)")
    print(f"  Failed          : {len(failed)}")
    if failed:
        print()
        print("  Failed institution IDs:")
        for inst_id, reason in failed:
            print(f"    - {inst_id}: {reason}")
    print("=" * 60)

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Migrate SkillChain institution keys from AES-GCM (DB) to HashiCorp Vault."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be migrated without writing anything.",
    )
    args = parser.parse_args()
    main(dry_run=args.dry_run)
