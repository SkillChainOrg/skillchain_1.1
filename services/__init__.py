"""
services/__init__.py — Artisan-first service index for SkillChain.

This module provides a single import point for the four core services.
The actual implementation files live at the project root; this directory
is a thin re-export layer for callers that prefer the services.* namespace.

Service responsibilities:
  did_service        — DID generation, artisan/institution identity, key management
  signing_service    — Ed25519 signing, Vault & AES-GCM key routing
  ipfs_service       — IPFS metadata pinning and retrieval (Pinata)
  algorand_service   — Algorand tx anchoring and credential verification
"""

# ── DID & identity ────────────────────────────────────────────────────────────
from did_service import (          # noqa: F401
    register_did,
    validate_api_key,
    verify_provenance,
    get_did_for_address,
    get_did_for_artisan_address,
)

# ── Signing ───────────────────────────────────────────────────────────────────
from signing_service import (      # noqa: F401
    resolve_private_key,           # canonical entry point (new code should use this)
    sign_credential_hash,
    sign_transaction,
    get_issuer_address,
    derive_institution_id,
    IDENTITY_SYSTEM,
    IDENTITY_ARTISAN,
    IDENTITY_INSTITUTION,
)

# ── IPFS ──────────────────────────────────────────────────────────────────────
from ipfs_service import (         # noqa: F401
    pin_with_retry,
    pin_certificate_metadata,
    fetch_certificate_metadata,
)

# ── Algorand ──────────────────────────────────────────────────────────────────
from algorand_service import (     # noqa: F401
    anchor_hash,
    verify_hash,
    generate_hmac,
    save_to_db,
)
