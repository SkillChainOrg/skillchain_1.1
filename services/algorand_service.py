"""
services/algorand_service.py — Algorand service layer.

Thin facade over the existing `algorand_service` implementation module at the
project root (which remains the source of truth and is still imported directly
by other modules). It exposes the blockchain helpers as a stable service
interface (`AlgorandService`) for orchestration/service code.

No behaviour is changed: every method delegates 1:1 to the root module.
"""

import algorand_service as _impl


class AlgorandService:
    """Service facade for Algorand node / indexer access and anchoring."""

    def get_algod_client(self):
        """Return a configured algod client."""
        return _impl.get_algod_client()

    def get_indexer_client(self, *, fallback: bool = False):
        """Return a configured indexer client (optionally the fallback endpoint)."""
        return _impl.get_indexer_client(fallback=fallback)

    def anchor_hash(self, *args, **kwargs):
        """Anchor a hash on-chain (delegates to the implementation module)."""
        return _impl.anchor_hash(*args, **kwargs)

    def verify_hash(self, *args, **kwargs):
        """Verify an anchored hash (delegates to the implementation module)."""
        return _impl.verify_hash(*args, **kwargs)
