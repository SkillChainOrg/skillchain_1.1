from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class PaymentRequest:
    provider: str
    provider_order_id: str
    amount: int
    currency: str
    public_key_id: str
    metadata: dict


@dataclass(frozen=True)
class VerifiedSettlement:
    provider: str
    provider_order_id: str
    provider_payment_id: str
    settlement_mode: str
    verified: bool
    metadata: dict


class CommerceProvider(Protocol):
    """
    Payment provider boundary.
    Provenance logic MUST NOT depend on provider specifics.
    """

    provider_name: str

    def create_payment_request(
        self, *, amount: int, currency: str, receipt: str, notes: dict
    ) -> PaymentRequest: ...

    def verify_payment(
        self, *, order_id: str, payment_id: str, signature: str
    ) -> VerifiedSettlement: ...
