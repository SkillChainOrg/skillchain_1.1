"""
digilocker_service.py — Mock DigiLocker provider for SkillChain (demo mode).

WHY THIS EXISTS
---------------
Production DigiLocker access via Setu requires registered-institution
credentials.  While those are being obtained, this module provides a
fully self-contained simulation that:

  • Behaves identically to the real Setu integration from the routes'
    perspective — same function signatures, same return shapes.
  • Lets the frontend exercise the complete consent → identity-bind → DID
    flow without any external network calls.
  • Is designed to be swapped out in a single diff: replace the two
    private helpers `_mock_create_request` and `_mock_get_status` with
    real HTTP calls to Setu, and nothing else in this file (or in the
    routes) needs to change.

MOCK FLOW
---------
1. /digilocker/start
       → create_digilocker_request()
       → stores a fake session in _FAKE_DIGILOCKER_DB
       → returns request_id + a fake redirect URL

2. /digilocker/callback?id=<request_id>
       → get_request_status()
       → the mock immediately marks the session "authenticated"
         (simulates the user clicking "Allow" in DigiLocker)
       → returns user details (name + stable digilocker_id)

3. /digilocker/verify  (identity-only — document/cert layer is a separate concern)
       → verify_with_identity()
       → reads user details from the mock store
       → normalises name, calls bind_identity() → DID
       → returns identity_did, digilocker_id, name

FUTURE SWAP POINTS
------------------
To restore real Setu calls, replace the bodies of:
    _mock_create_request()        → POST https://dg-sandbox.setu.co/api/digilocker
    _mock_get_status()            → GET  https://dg-sandbox.setu.co/api/digilocker/{id}

The rest of this module — verify_with_identity, bind_identity call, and the
response structure — does not need to change.
"""

import logging
import uuid

log = logging.getLogger(__name__)


# ── In-memory mock store ───────────────────────────────────────────────────────
#
# Maps  request_id → { "name": str, "digilocker_id": str, "status": str }
#
# Intentionally module-level so it survives across requests within a single
# Flask worker process (sufficient for demo / development).  For multi-worker
# or multi-process deployments, replace with Redis or a DB-backed session table
# using the same key → value interface.

_FAKE_DIGILOCKER_DB: dict = {}

# Fixed demo identity.  Change these constants (or read them from env vars) to
# simulate a different verified user in the demo environment.
_DEMO_USER_NAME = "Aarav Sharma"


# ── Mock helpers (SWAP THESE for real Setu calls) ─────────────────────────────
#
# These two functions are the ONLY pieces that need to change when migrating to
# real Setu API credentials.  The public API and all route handlers stay the
# same.

def _mock_create_request(redirect_url: str) -> dict:
    """
    Simulate a Setu POST /api/digilocker call.

    Generates a fresh session, pre-populates the in-memory DB with a demo
    user (auto-authenticated), and returns the same shape Setu would.

    ── REAL SETU REPLACEMENT ─────────────────────────────────────────────────
    import requests, os
    BASE_URL = os.getenv("SETU_BASE_URL", "https://dg-sandbox.setu.co")
    response = requests.post(
        f"{BASE_URL}/api/digilocker",
        headers=setu_headers(),
        json={"redirectUrl": redirect_url},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    return {
        "request_id":     data["id"],
        "digilocker_url": data["url"],
        "expires_at":     data["validUpto"],
    }
    ──────────────────────────────────────────────────────────────────────────
    """
    request_id = str(uuid.uuid4())

    # Derive a stable, deterministic digilocker_id from the request_id prefix.
    # In production this comes from Setu as a stable per-user UID.
    digilocker_id = f"DL-{request_id[:8]}"

    _FAKE_DIGILOCKER_DB[request_id] = {
        "name":          _DEMO_USER_NAME,
        "digilocker_id": digilocker_id,
        # Auto-authenticate: simulates the user clicking "Allow" in DigiLocker.
        "status":        "authenticated",
    }

    log.info("[MOCK] DigiLocker session created: request_id=%s  digilocker_id=%s",
             request_id, digilocker_id)

    return {
        "request_id":     request_id,
        # A placeholder URL the frontend can display; no real redirect in demo.
        "digilocker_url": f"https://mock.digilocker.demo/consent?id={request_id}",
        "expires_at":     "2099-12-31T23:59:59Z",
    }


def _mock_get_status(request_id: str) -> dict:
    """
    Simulate a Setu GET /api/digilocker/{id} call.

    Returns status + user details from the in-memory store.  Because the mock
    auto-authenticates at creation time, this always returns "authenticated"
    for a known request_id — no polling required.

    ── REAL SETU REPLACEMENT ─────────────────────────────────────────────────
    import requests, os
    BASE_URL = os.getenv("SETU_BASE_URL", "https://dg-sandbox.setu.co")
    response = requests.get(
        f"{BASE_URL}/api/digilocker/{request_id}",
        headers=setu_headers(),
        timeout=10,
    )
    data = response.json()
    return {
        "status":     data.get("status"),
        "user":       data.get("digilockerUserDetails", {}),
        "request_id": request_id,
    }
    ──────────────────────────────────────────────────────────────────────────
    """
    session = _FAKE_DIGILOCKER_DB.get(request_id)
    if not session:
        log.warning("[MOCK] get_status called for unknown request_id=%s", request_id)
        return {"status": "not_found", "user": {}, "request_id": request_id}

    return {
        "status":     session["status"],
        "request_id": request_id,
        # Mirror the shape of Setu's digilockerUserDetails block.
        "user": {
            "id":   session["digilocker_id"],
            "name": session["name"],
        },
    }


# ── Public API — identical signatures to the real Setu integration ─────────────
#
# Routes import only these names.  None of the routes change when swapping to
# real Setu API calls; only the private helpers above change.

def create_digilocker_request(redirect_url: str) -> dict:
    """
    Start a DigiLocker session.

    Returns:
        request_id      — opaque session token (pass to callback + verify)
        digilocker_url  — URL to redirect or display to the user
        expires_at      — ISO-8601 session expiry timestamp
    """
    return _mock_create_request(redirect_url)


def get_request_status(request_id: str) -> dict:
    """
    Retrieve current consent status and user details for a session.

    Returns:
        status      — "authenticated" | "pending" | "not_found"
        user        — dict with at least {id, name} when authenticated
        request_id  — echoed back for convenience
    """
    return _mock_get_status(request_id)


def ensure_mock_session(request_id: str) -> dict:
    """
    Idempotently create a mock session for a known request_id.

    DEMO-ONLY helper.  Called by /digilocker/callback when the session is
    missing from the in-memory store (e.g. the Flask server restarted between
    /start and /callback, wiping _FAKE_DIGILOCKER_DB).

    Instead of returning 403 and killing the presentation, this re-creates
    the session deterministically — same request_id always produces the same
    digilocker_id and demo name — so the rest of the flow continues unchanged.

    This function should NOT exist in the real Setu integration (sessions live
    on Setu's servers and survive our restarts).  Remove it — or make it a
    no-op — when switching to real API calls.
    """
    digilocker_id = f"DL-{request_id[:8]}"

    # Only write if the key is genuinely absent (guard against a race where
    # two requests arrive simultaneously for the same id).
    if request_id not in _FAKE_DIGILOCKER_DB:
        _FAKE_DIGILOCKER_DB[request_id] = {
            "name":          _DEMO_USER_NAME,
            "digilocker_id": digilocker_id,
            "status":        "authenticated",
        }
        log.info(
            "[MOCK] Session re-created at callback (server likely restarted): "
            "request_id=%s  digilocker_id=%s",
            request_id, digilocker_id,
        )

    return _mock_get_status(request_id)


def _get_digilocker_user_details(request_id: str) -> dict:
    """
    Return just the user-details block for a completed session.

    Internal helper consumed by verify_with_identity.  Callers expect:
        id   — stable DigiLocker user identifier (identity anchor key)
        name — government-verified Aadhaar name
    """
    return _mock_get_status(request_id).get("user", {})


# ── Identity verification entry point ─────────────────────────────────────────

def verify_with_identity(request_id: str) -> dict:
    """
    Identity-only DigiLocker verification with DID binding.

    This is the identity stage of the pipeline.  Document fetching,
    certificate hashing, and blockchain anchoring are intentionally out of
    scope here — they layer on top once real DigiLocker credentials are
    available.  Keeping this function focused on identity makes it easy to
    compose with the document/cert layer later.

    Flow
    ----
    1. Fetch user details via _get_digilocker_user_details().
    2. Validate that both name and digilocker_id are present.
    3. Normalise the name (strip + lower) — must match what identity_service
       uses so hashes are consistent.
    4. Call bind_identity() — idempotent: creates the anchor on first call,
       returns the existing DID on subsequent calls for the same user.
    5. Return a structured response the route can return directly as JSON.

    Args:
        request_id: Session ID returned by create_digilocker_request().

    Returns (success):
        success        — True
        identity_did   — did:skillchain:identity:<16-char-hash>
        digilocker_id  — stable user identifier (e.g. "DL-a1b2c3d4" in mock)
        name           — normalised name stored in the identity anchor
        anchor_new     — True if this is the first bind for this user

    Returns (failure):
        success        — False
        reason         — human-readable explanation
    """
    # Import here to avoid a circular import at module load time.
    from identity_service import bind_identity

    # Step 1 — retrieve user details from the session ─────────────────────────
    user          = _get_digilocker_user_details(request_id)
    digilocker_id = user.get("id", "").strip()
    raw_name      = user.get("name", "").strip()

    # Step 2 — guard against incomplete sessions ───────────────────────────────
    if not digilocker_id or not raw_name:
        log.warning(
            "[MOCK] Incomplete session data for request_id=%s  "
            "digilocker_id=%r  name=%r",
            request_id, digilocker_id, raw_name,
        )
        return {
            "success": False,
            "reason": (
                "DigiLocker session returned incomplete identity data. "
                "The session may have expired or consent was not granted."
            ),
        }

    # Step 3 — normalise name ─────────────────────────────────────────────────
    # identity_service._normalize_name() applies the same transform, but we do
    # it explicitly here so the "name" field in our response always reflects
    # what was actually written into the identity anchor.
    normalised_name = raw_name.strip().lower()

    # Step 4 — bind identity → DID (idempotent) ───────────────────────────────
    try:
        anchor = bind_identity(digilocker_id, normalised_name)
    except Exception as exc:
        log.error(
            "Identity binding failed  digilocker_id=%s  error=%s",
            digilocker_id, exc,
        )
        return {
            "success": False,
            "reason":  f"Identity binding failed: {exc}",
        }

    log.info(
        "Identity bound  did=%s  new=%s",
        anchor["identity_did"], anchor["created"],
    )

    # Step 5 — return identity result ─────────────────────────────────────────
    return {
        "success":       True,
        "identity_did":  anchor["identity_did"],
        "digilocker_id": digilocker_id,
        "name":          normalised_name,
        "anchor_new":    anchor["created"],   # True = first bind; False = returning user
    }