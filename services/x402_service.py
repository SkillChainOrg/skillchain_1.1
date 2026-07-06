"""
services/x402_service.py — X402 service layer.

This is the service-layer entry point for the Algorand x402 acquisition flow.
It is a thin facade over the existing implementation module (`x402_service` at
the project root), which remains the working source of truth and is still
imported directly by callers such as startup migrations.

The facade exists so that route/orchestration code depends on a stable service
interface (`X402Service`) rather than on free functions. This prepares the
codebase for the later facilitator phase, where the internals of the challenge
/ verify steps can be redirected to a dedicated facilitator without touching
callers of this class.

No behaviour is changed: every method delegates 1:1 to the root module.
"""

from typing import Any

import x402_service as _impl


class X402Service:
    """Service facade for x402 payment challenges and settlement verification."""

    def init_db(self) -> None:
        """Create the x402 challenge table / indexes (idempotent)."""
        return _impl.init_x402_db()

    def create_payment_requirements(
        self,
        *,
        artwork_id: int,
        collector_name: str = "",
        collector_email: str = "",
    ) -> dict[str, Any]:
        """Issue an x402 challenge and return the payment requirements payload."""
        return _impl.create_payment_requirements(
            artwork_id=artwork_id,
            collector_name=collector_name,
            collector_email=collector_email,
        )

    def verify_payment(
        self,
        *,
        tx_id: str,
        wallet_address: str,
        challenge_nonce: str,
    ) -> dict[str, Any]:
        """Verify a grouped Algorand settlement against an issued challenge."""
        return _impl.verify_x402_payment(
            tx_id=tx_id,
            wallet_address=wallet_address,
            challenge_nonce=challenge_nonce,
        )

    def get_artwork_row(self, artwork_id: int) -> dict[str, Any]:
        """Load the artwork row backing a challenge (raises KeyError if absent)."""
        return _impl._get_artwork_row(artwork_id)
