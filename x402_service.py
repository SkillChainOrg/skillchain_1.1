import base64
import hashlib
import json
import os
import secrets
import time
from typing import Any

from algosdk import abi, encoding

from algorand_service import get_algod_client, get_indexer_client
from db import dict_cursor, get_db_connection


NETWORK = os.getenv("X402_NETWORK", "algorand-testnet")
NONCE_TTL_SECONDS = int(os.getenv("X402_CHALLENGE_TTL_SECONDS", "900"))
OWNER_BOX_PREFIX = os.getenv("ARTWORK_MARKETPLACE_OWNER_BOX_PREFIX", "owner:")
PRICE_BOX_PREFIX = os.getenv("ARTWORK_MARKETPLACE_PRICE_BOX_PREFIX", "price:")
ACQUIRE_SIGNATURE = "acquire(string)bool"


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _unix_now() -> int:
    return int(time.time())


def _required_env(name: str) -> str:
    value = (os.getenv(name) or "").strip()
    if not value:
        raise RuntimeError(f"{name} is required for x402 settlement")
    return value


def _get_marketplace_config() -> dict[str, Any]:
    return {
        "app_id": int(_required_env("ARTWORK_MARKETPLACE_APP_ID")),
        "receiver": _required_env("ARTWORK_MARKETPLACE_RECEIVER"),
        "network": NETWORK,
        "owner_box_prefix": OWNER_BOX_PREFIX,
        "price_box_prefix": PRICE_BOX_PREFIX,
    }


def _get_price_overrides() -> dict[str, int]:
    raw = (os.getenv("ARTWORK_PRICE_MICROALGOS_MAP") or "").strip()
    if not raw:
        return {}
    parsed = json.loads(raw)
    return {str(key): int(value) for key, value in parsed.items()}


def _get_artwork_row(artwork_id: int) -> dict[str, Any]:
    conn = get_db_connection()
    cur = dict_cursor(conn)
    try:
        cur.execute("SELECT * FROM artworks WHERE id = %s", (artwork_id,))
        row = cur.fetchone()
        if not row:
            raise KeyError("Artwork not found")
        return dict(row)
    finally:
        cur.close()
        conn.close()


def _resolve_artwork_price_microalgos(artwork_id: int) -> int:
    overrides = _get_price_overrides()
    if str(artwork_id) in overrides:
        return int(overrides[str(artwork_id)])

    default_price = os.getenv("DEFAULT_ARTWORK_PRICE_MICROALGOS")
    if default_price:
        return int(default_price)

    raise RuntimeError(
        "Configure DEFAULT_ARTWORK_PRICE_MICROALGOS or ARTWORK_PRICE_MICROALGOS_MAP"
    )


def _collector_reference_id(email: str) -> str:
    normalized = (email or "").strip().lower()
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]


def init_x402_db() -> None:
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
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
            """
        )
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uidx_x402_payment_challenges_nonce ON x402_payment_challenges (nonce)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_x402_payment_challenges_artwork_id ON x402_payment_challenges (artwork_id)"
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()


def create_payment_requirements(
    *, artwork_id: int, collector_name: str = "", collector_email: str = ""
) -> dict[str, Any]:
    artwork = _get_artwork_row(artwork_id)
    config = _get_marketplace_config()
    amount = _resolve_artwork_price_microalgos(artwork_id)
    nonce = secrets.token_urlsafe(24)
    now = _unix_now()
    created_at = _utc_now()
    expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + NONCE_TTL_SECONDS))
    acquisition_id = f"x402_{nonce[:18]}"

    collector_reference_id = _collector_reference_id(collector_email)

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        if collector_reference_id:
            cur.execute(
                """
                INSERT INTO collectors (collector_reference_id, collector_name, collector_email, created_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (collector_reference_id) DO UPDATE SET
                    collector_name = EXCLUDED.collector_name,
                    collector_email = EXCLUDED.collector_email
                """,
                (
                    collector_reference_id,
                    collector_name.strip(),
                    collector_email.strip(),
                    created_at,
                ),
            )

        cur.execute(
            """
            INSERT INTO acquisitions
                (acquisition_id, artwork_id, artist_did, buyer_name, buyer_email, collector_reference_id,
                 amount, currency, payment_status, settlement_mode, challenge_nonce, algorand_app_id, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                acquisition_id,
                artwork_id,
                artwork.get("artisan_did"),
                collector_name.strip(),
                collector_email.strip(),
                collector_reference_id or None,
                amount,
                "ALGO",
                "challenge_issued",
                "algorand_x402",
                nonce,
                config["app_id"],
                created_at,
            ),
        )

        cur.execute(
            """
            INSERT INTO x402_payment_challenges
                (nonce, artwork_id, acquisition_id, collector_name, collector_email,
                 amount_microalgos, receiver, app_id, network, expires_at, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                nonce,
                artwork_id,
                acquisition_id,
                collector_name.strip(),
                collector_email.strip(),
                amount,
                config["receiver"],
                config["app_id"],
                config["network"],
                expires_at,
                created_at,
            ),
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()

    artwork_id_str = str(artwork_id)
    return {
        "amount": amount,
        "asset": "ALGO",
        "network": config["network"],
        "app_id": config["app_id"],
        "receiver": config["receiver"],
        "challenge_nonce": nonce,
        "artwork_id": artwork_id_str,
        "expires_at": expires_at,
        "method": ACQUIRE_SIGNATURE,
        "boxes": [
            {"name": f"{config['owner_box_prefix']}{artwork_id_str}"},
            {"name": f"{config['price_box_prefix']}{artwork_id_str}"},
            {"name": f"creator:{artwork_id_str}"},
        ],
        "artwork": {
            "id": artwork.get("id"),
            "title": artwork.get("title"),
            "artisan_did": artwork.get("artisan_did"),
        },
    }


def _load_challenge(nonce: str) -> dict[str, Any] | None:
    conn = get_db_connection()
    cur = dict_cursor(conn)
    try:
        cur.execute(
            """
            SELECT *
            FROM x402_payment_challenges
            WHERE nonce = %s
            LIMIT 1
            """,
            (nonce,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        cur.close()
        conn.close()


def _selector_bytes() -> bytes:
    return abi.Method.from_signature(ACQUIRE_SIGNATURE).get_selector()


def _decode_b64(value: str | bytes | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return base64.b64decode(value)


def _decode_artwork_arg(arg_b64: str) -> str:
    string_type = abi.ABIType.from_string("string")
    return str(string_type.decode(_decode_b64(arg_b64)))


def _search_group_transactions(group_id: str) -> list[dict[str, Any]]:
    client = get_indexer_client()
    response = client.search_transactions(group_id=group_id)
    return response.get("transactions", [])


def _find_matching_payment(
    transactions: list[dict[str, Any]],
    *,
    sender: str,
    receiver: str,
    minimum_amount: int,
) -> dict[str, Any] | None:
    for txn in transactions:
        payment = txn.get("payment-transaction")
        if not payment:
            continue
        if txn.get("sender") != sender:
            continue
        if payment.get("receiver") != receiver:
            continue
        if int(payment.get("amount", 0)) < int(minimum_amount):
            continue
        return txn
    return None


def _read_owner_from_box(*, app_id: int, artwork_id: int) -> str:
    client = get_algod_client()
    box_name = f"{OWNER_BOX_PREFIX}{artwork_id}".encode("utf-8")
    box = client.application_box_by_name(app_id, box_name)
    raw_value = box.get("value", "")
    value_bytes = _decode_b64(raw_value)
    return encoding.encode_address(value_bytes)


def _mark_challenge_used(
    *,
    nonce: str,
    wallet_address: str,
    tx_id: str,
    group_id: str,
) -> None:
    used_at = _utc_now()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE x402_payment_challenges
            SET wallet_address = %s,
                tx_id = %s,
                group_id = %s,
                status = 'settled',
                used_at = %s
            WHERE nonce = %s
            """,
            (wallet_address, tx_id, group_id, used_at, nonce),
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()


def _persist_successful_acquisition(
    *,
    challenge: dict[str, Any],
    wallet_address: str,
    tx_id: str,
    group_id: str,
    payment_tx_id: str,
) -> dict[str, Any]:
    now = _utc_now()
    collector_reference_id = _collector_reference_id(challenge.get("collector_email") or "")
    acquisition_id = challenge.get("acquisition_id")
    artwork_id = int(challenge["artwork_id"])
    explorer_url = f"https://testnet.explorer.perawallet.app/tx/{tx_id}"
    event = {
        "provenance_event_type": "acquired",
        "event_type": "ownership_transferred_onchain",
        "timestamp": now,
        "wallet_address": wallet_address,
        "app_call_tx_id": tx_id,
        "payment_tx_id": payment_tx_id,
        "group_id": group_id,
        "app_id": int(challenge["app_id"]),
        "network": challenge["network"],
        "challenge_nonce": challenge["nonce"],
        "verified": True,
    }

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE acquisitions
            SET payment_status = 'paid',
                settlement_mode = 'algorand_x402',
                algorand_tx_id = %s,
                algorand_group_id = %s,
                wallet_address = %s,
                algorand_app_id = %s,
                timestamp = %s
            WHERE acquisition_id = %s
            """,
            (tx_id, group_id, wallet_address, int(challenge["app_id"]), now, acquisition_id),
        )

        cur.execute(
            """
            INSERT INTO artwork_ownership
                (artwork_id, acquisition_id, owner_name, owner_email, owner_wallet, collector_reference_id, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (artwork_id) DO UPDATE SET
                acquisition_id = EXCLUDED.acquisition_id,
                owner_name = EXCLUDED.owner_name,
                owner_email = EXCLUDED.owner_email,
                owner_wallet = EXCLUDED.owner_wallet,
                collector_reference_id = EXCLUDED.collector_reference_id,
                updated_at = EXCLUDED.updated_at
            """,
            (
                artwork_id,
                acquisition_id,
                challenge.get("collector_name"),
                challenge.get("collector_email"),
                wallet_address,
                collector_reference_id or None,
                now,
            ),
        )

        cur.execute(
            """
            INSERT INTO artwork_provenance_events
                (artwork_id, provenance_event_type, event_type, event_json, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                artwork_id,
                "acquired",
                "ownership_transferred_onchain",
                json.dumps(event),
                now,
            ),
        )

        cur.execute(
            "UPDATE artworks SET status = 'acquired' WHERE id = %s",
            (artwork_id,),
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()

    return {
        "status": "ownership_transferred",
        "artwork_id": artwork_id,
        "owner_wallet": wallet_address,
        "network": challenge["network"],
        "app_id": int(challenge["app_id"]),
        "tx_id": tx_id,
        "payment_tx_id": payment_tx_id,
        "group_id": group_id,
        "updated_at": now,
        "provenance_event": "ownership_transferred_onchain",
        "explorer_url": explorer_url,
        "settlement": {
            "status": "verified",
            "network": challenge["network"],
            "amount": int(challenge["amount_microalgos"]),
            "currency": "ALGO",
            "receiver": challenge["receiver"],
            "app_call_tx_id": tx_id,
            "payment_tx_id": payment_tx_id,
            "group_id": group_id,
            "settlement_reference": tx_id,
            "verified_at": now,
            "verification_mode": "algorand_grouped_transaction",
        },
    }


def verify_x402_payment(
    *, tx_id: str, wallet_address: str, challenge_nonce: str
) -> dict[str, Any]:
    challenge = _load_challenge(challenge_nonce)
    if not challenge:
        return {"verified": False, "reason": "challenge_not_found"}

    if challenge.get("status") != "pending":
        return {"verified": False, "reason": "challenge_already_used"}

    expires_at = challenge.get("expires_at") or ""
    if expires_at and expires_at < _utc_now():
        return {"verified": False, "reason": "challenge_expired"}

    indexer = get_indexer_client()
    app_txn = indexer.transaction(tx_id).get("transaction", {})
    if not app_txn:
        return {"verified": False, "reason": "transaction_not_found"}
    if not app_txn.get("confirmed-round"):
        return {"verified": False, "reason": "transaction_not_confirmed"}
    if app_txn.get("sender") != wallet_address:
        return {"verified": False, "reason": "wallet_address_mismatch"}

    app_call = app_txn.get("application-transaction") or {}
    if int(app_call.get("application-id", 0)) != int(challenge["app_id"]):
        return {"verified": False, "reason": "app_id_mismatch"}

    app_args = app_call.get("application-args") or []
    if len(app_args) < 2:
        return {"verified": False, "reason": "missing_app_arguments"}

    if _decode_b64(app_args[0]) != _selector_bytes():
        return {"verified": False, "reason": "unexpected_method_selector"}

    submitted_artwork_id = _decode_artwork_arg(app_args[1])
    if submitted_artwork_id != str(challenge["artwork_id"]):
        return {"verified": False, "reason": "artwork_id_mismatch"}

    group_id = app_txn.get("group")
    if not group_id:
        return {"verified": False, "reason": "missing_group_id"}

    grouped_transactions = _search_group_transactions(group_id)
    payment_txn = _find_matching_payment(
        grouped_transactions,
        sender=wallet_address,
        receiver=challenge["receiver"],
        minimum_amount=int(challenge["amount_microalgos"]),
    )
    if not payment_txn:
        return {"verified": False, "reason": "grouped_payment_not_found"}

    try:
        current_owner = _read_owner_from_box(
            app_id=int(challenge["app_id"]),
            artwork_id=int(challenge["artwork_id"]),
        )
    except Exception:
        return {"verified": False, "reason": "owner_box_lookup_failed"}

    if current_owner != wallet_address:
        return {"verified": False, "reason": "ownership_not_updated"}

    _mark_challenge_used(
        nonce=challenge_nonce,
        wallet_address=wallet_address,
        tx_id=tx_id,
        group_id=group_id,
    )

    result = _persist_successful_acquisition(
        challenge=challenge,
        wallet_address=wallet_address,
        tx_id=tx_id,
        group_id=group_id,
        payment_tx_id=payment_txn["id"],
    )
    return {"verified": True, **result}
