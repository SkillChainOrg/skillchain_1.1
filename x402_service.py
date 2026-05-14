"""
Minimal x402 helpers for the SkillChain acquisition MVP.

This module intentionally stays demo-focused:
- declare payment requirements for a protected resource
- detect a mock payment proof in request headers
- return a placeholder settlement record for downstream ownership updates
"""

import time
from typing import Mapping


X402_PAYMENT_HEADER = "X-X402-Payment"
X402_WALLET_HEADER = "X-X402-Wallet"
X402_EXPECTED_PROOF = "paid-demo-proof"


def create_payment_requirements() -> dict:
    return {
        "amount": "1",
        "currency": "USDC",
        "network": "algorand-testnet",
        "description": "Acquire artwork ownership",
    }


def verify_x402_payment(headers: Mapping[str, str]) -> dict:
    payment_proof = (headers.get(X402_PAYMENT_HEADER) or "").strip()
    wallet_address = (headers.get(X402_WALLET_HEADER) or "").strip()

    if payment_proof != X402_EXPECTED_PROOF:
        return {
            "verified": False,
            "reason": "missing_or_invalid_payment_proof",
        }

    return {
        "verified": True,
        "wallet_address": wallet_address or "wallet_address",
        "settlement": {
            "status": "verified",
            "network": "algorand-testnet",
            "currency": "USDC",
            "amount": "1",
            "settlement_reference": payment_proof,
            "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "verification_mode": "mock_x402_header",
        },
    }
