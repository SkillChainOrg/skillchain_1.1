import hashlib
import os
import time
import uuid

from db import get_db_connection, dict_cursor
from services.commerce.providers.razorpay_provider import RazorpayProvider


SETTLEMENT_DOMESTIC_UPI = "domestic_upi"


def _default_amount_paise() -> int:
    # Intentionally conservative; can be overridden per deployment without schema changes.
    val = os.getenv("ARTWORK_ACQUISITION_AMOUNT_PAISE") or os.getenv(
        "DEFAULT_ACQUISITION_AMOUNT_PAISE"
    )
    if not val:
        return 200_000  # Rs 2000
    return int(val)


def compute_artwork_amount_paise(artwork: dict) -> int:
    # Future: price tiers per artwork. For v1: env-configured.
    return _default_amount_paise()


def create_acquisition_order(
    *, artwork_id: int, buyer_name: str, buyer_email: str
) -> dict:
    """
    Create a Razorpay order and persist a pending acquisition.

    Returns payload for frontend checkout:
      { key_id, order_id, amount, currency, acquisition_id, artwork }
    """
    if not isinstance(artwork_id, int):
        raise TypeError("artwork_id must be int")
    buyer_name = (buyer_name or "").strip()
    buyer_email = (buyer_email or "").strip()
    if not buyer_name:
        raise ValueError("buyer_name is required")
    if not buyer_email or "@" not in buyer_email:
        raise ValueError("buyer_email is invalid")

    conn = get_db_connection()
    cur = dict_cursor(conn)
    try:
        cur.execute("SELECT * FROM artworks WHERE id = %s", (artwork_id,))
        artwork_row = cur.fetchone()
        if not artwork_row:
            raise KeyError("Artwork not found")
        artwork = dict(artwork_row)
    finally:
        cur.close()
        conn.close()

    amount = compute_artwork_amount_paise(artwork)
    currency = "INR"
    acquisition_id = uuid.uuid4().hex
    receipt = f"sc_acq_{acquisition_id[:12]}"
    collector_reference_id = hashlib.sha256(
        buyer_email.strip().lower().encode("utf-8")
    ).hexdigest()[:32]

    provider = RazorpayProvider()
    pr = provider.create_payment_request(
        amount=amount,
        currency=currency,
        receipt=receipt,
        notes={
            "skillchain_acquisition_id": acquisition_id,
            "artwork_id": str(artwork_id),
            "intent": "acquire_artwork",
        },
    )

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn2 = get_db_connection()
    cur2 = conn2.cursor()
    try:
        cur2.execute(
            """
            INSERT INTO collectors (collector_reference_id, collector_name, collector_email, created_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (collector_reference_id) DO UPDATE SET
                collector_name = EXCLUDED.collector_name,
                collector_email = EXCLUDED.collector_email
            """,
            (collector_reference_id, buyer_name, buyer_email, now),
        )
        cur2.execute(
            """
            INSERT INTO acquisitions
                (acquisition_id, artwork_id, artist_did, buyer_name, buyer_email, collector_reference_id,
                 amount, currency, razorpay_order_id, payment_status, settlement_mode, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s,
                    %s, %s, %s, 'created', %s, %s)
            """,
            (
                acquisition_id,
                artwork_id,
                artwork.get("artisan_did"),
                buyer_name,
                buyer_email,
                collector_reference_id,
                amount,
                currency,
                pr.provider_order_id,
                SETTLEMENT_DOMESTIC_UPI,
                now,
            ),
        )
        conn2.commit()
    finally:
        cur2.close()
        conn2.close()

    return {
        "key_id": pr.public_key_id,
        "order_id": pr.provider_order_id,
        "amount": pr.amount,
        "currency": pr.currency,
        "acquisition_id": acquisition_id,
        "artwork": {
            "id": artwork.get("id"),
            "title": artwork.get("title"),
            "artisan_did": artwork.get("artisan_did"),
            "ipfs_cid": artwork.get("ipfs_cid"),
            "tx_id": artwork.get("tx_id"),
        },
    }


def record_successful_acquisition(
    *, artwork_id: int, order_id: str, payment_id: str, signature: str
) -> dict:
    """
    Mark acquisition paid, append provenance event, and update ownership metadata.
    """
    provider = RazorpayProvider()
    settlement = provider.verify_payment(
        order_id=order_id, payment_id=payment_id, signature=signature
    )
    if not settlement.verified:
        return {"ok": False, "reason": "signature_invalid"}

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    conn = get_db_connection()
    cur = dict_cursor(conn)
    try:
        cur.execute(
            """
            SELECT *
            FROM acquisitions
            WHERE artwork_id = %s AND razorpay_order_id = %s
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (artwork_id, order_id),
        )
        acq = cur.fetchone()
        if not acq:
            return {"ok": False, "reason": "acquisition_not_found"}
        acq = dict(acq)
    finally:
        cur.close()
        conn.close()

    conn2 = get_db_connection()
    cur2 = conn2.cursor()
    try:
        cur2.execute(
            """
            UPDATE acquisitions
            SET razorpay_payment_id = %s,
                payment_status = 'paid',
                timestamp = %s
            WHERE acquisition_id = %s
            """,
            (payment_id, now, acq["acquisition_id"]),
        )

        cur2.execute(
            """
            INSERT INTO artwork_ownership (artwork_id, acquisition_id, owner_name, owner_email, collector_reference_id, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (artwork_id) DO UPDATE SET
                acquisition_id = EXCLUDED.acquisition_id,
                owner_name     = EXCLUDED.owner_name,
                owner_email    = EXCLUDED.owner_email,
                collector_reference_id = EXCLUDED.collector_reference_id,
                updated_at     = EXCLUDED.updated_at
            """,
            (
                artwork_id,
                acq["acquisition_id"],
                acq["buyer_name"],
                acq["buyer_email"],
                acq.get("collector_reference_id"),
                now,
            ),
        )

        event = {
            "provenance_event_type": "acquired",
            "event_type": "acquisition_recorded",
            "timestamp": now,
            "payment_id": payment_id,
            "razorpay_order_id": order_id,
            "settlement_mode": acq.get("settlement_mode")
            or SETTLEMENT_DOMESTIC_UPI,
            "verified": True,
        }
        import json as _j

        cur2.execute(
            """
            INSERT INTO artwork_provenance_events (artwork_id, provenance_event_type, event_type, event_json, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (artwork_id, "acquired", "acquisition_recorded", _j.dumps(event), now),
        )

        cur2.execute("UPDATE artworks SET status = 'acquired' WHERE id = %s", (artwork_id,))

        conn2.commit()
    finally:
        cur2.close()
        conn2.close()

    return {
        "ok": True,
        "acquisition_id": acq["acquisition_id"],
        "artwork_id": artwork_id,
        "payment_id": payment_id,
        "settlement_mode": acq.get("settlement_mode") or SETTLEMENT_DOMESTIC_UPI,
        "timestamp": now,
    }
