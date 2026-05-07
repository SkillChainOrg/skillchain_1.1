import hashlib
import hmac
import os

import razorpay

from .base import PaymentRequest, VerifiedSettlement


class RazorpayProvider:
    provider_name = "razorpay"
    settlement_mode = "domestic_upi"

    def __init__(self) -> None:
        self._key_id = os.getenv("RAZORPAY_KEY_ID") or ""
        self._key_secret = os.getenv("RAZORPAY_KEY_SECRET") or ""
        if not self._key_id or not self._key_secret:
            raise RuntimeError(
                "Razorpay is not configured (RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET missing)."
            )
        self._client = razorpay.Client(auth=(self._key_id, self._key_secret))

    def create_payment_request(
        self, *, amount: int, currency: str, receipt: str, notes: dict
    ) -> PaymentRequest:
        order = self._client.order.create(
            {
                "amount": int(amount),
                "currency": currency,
                "receipt": receipt,
                "notes": notes or {},
            }
        )
        return PaymentRequest(
            provider=self.provider_name,
            provider_order_id=order.get("id"),
            amount=order.get("amount"),
            currency=order.get("currency", currency),
            public_key_id=self._key_id,
            metadata={"order": order},
        )

    def verify_payment(
        self, *, order_id: str, payment_id: str, signature: str
    ) -> VerifiedSettlement:
        order_id = (order_id or "").strip()
        payment_id = (payment_id or "").strip()
        signature = (signature or "").strip()
        msg = f"{order_id}|{payment_id}".encode("utf-8")
        expected = hmac.new(
            self._key_secret.encode("utf-8"), msg, hashlib.sha256
        ).hexdigest()
        ok = hmac.compare_digest(expected, signature)
        return VerifiedSettlement(
            provider=self.provider_name,
            provider_order_id=order_id,
            provider_payment_id=payment_id,
            settlement_mode=self.settlement_mode,
            verified=bool(ok),
            metadata={},
        )
