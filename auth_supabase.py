"""
auth_supabase.py — Supabase JWT verification for the SkillChain Flask backend.

Why this module exists
----------------------
Authentication (Google OAuth + phone) is handled entirely on the frontend by
Supabase. The backend's only job is to *verify* the Supabase-issued access token
on each protected request, extract the Supabase user id (the JWT ``sub`` claim),
and load the matching row from the existing ``artisans`` table (keyed by
``supabase_id``).

This module intentionally does NOT:
  - create or manage wallets / keys (see app.py + signing_service.py),
  - touch the Vault integration (see vault_client.py),
  - issue its own tokens.

It only validates the trust that Supabase already established.

Token verification
------------------
Supabase access tokens are standard JWTs. Two signing schemes are supported and
auto-detected from the token header ``alg``:

  - HS256  → symmetric, signed with the project "JWT secret"
             (Supabase dashboard → Project Settings → API → JWT Secret).
             Configure via ``SUPABASE_JWT_SECRET``.
  - ES256 / RS256 → asymmetric "signing keys". The public keys are fetched from
             the project JWKS endpoint and cached. Configure via ``SUPABASE_URL``
             (e.g. https://<ref>.supabase.co) or ``SUPABASE_JWKS_URL``.

Environment variables
---------------------
  SUPABASE_JWT_SECRET   HS256 shared secret (legacy / symmetric projects).
  SUPABASE_URL          Project URL; JWKS is derived as
                        ``<SUPABASE_URL>/auth/v1/.well-known/jwks.json``.
  SUPABASE_JWKS_URL     Explicit JWKS URL (overrides SUPABASE_URL derivation).
  SUPABASE_JWT_AUD      Expected audience claim. Default: ``authenticated``.
  SUPABASE_JWT_LEEWAY   Clock-skew leeway in seconds. Default: ``10``.

At least one of SUPABASE_JWT_SECRET / SUPABASE_URL / SUPABASE_JWKS_URL must be
set, otherwise verification fails closed (401).
"""

from __future__ import annotations

import logging
import os
from functools import wraps

import jwt
from flask import current_app, g, jsonify, request

from db import dict_cursor, get_db_connection

log = logging.getLogger(__name__)

# ── Configuration (read lazily so tests / env reloads behave) ──────────────────

_DEFAULT_AUD = "authenticated"


def _jwt_secret() -> str | None:
    return os.getenv("SUPABASE_JWT_SECRET")


def _expected_audience() -> str:
    return os.getenv("SUPABASE_JWT_AUD", _DEFAULT_AUD)


def _leeway_seconds() -> int:
    try:
        return int(os.getenv("SUPABASE_JWT_LEEWAY", "10"))
    except ValueError:
        return 10


def _jwks_url() -> str | None:
    explicit = os.getenv("SUPABASE_JWKS_URL")
    if explicit:
        return explicit
    base = os.getenv("SUPABASE_URL")
    if base:
        return f"{base.rstrip('/')}/auth/v1/.well-known/jwks.json"
    return None


# ── Errors ─────────────────────────────────────────────────────────────────────

class AuthError(Exception):
    """Raised when a request cannot be authenticated. Always maps to HTTP 401."""

    def __init__(self, message: str, *, detail: str | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail


# ── JWKS client cache (PyJWT handles its own key caching internally) ───────────

_jwks_client: "jwt.PyJWKClient | None" = None
_jwks_client_url: str | None = None


def _get_jwks_client(url: str) -> "jwt.PyJWKClient":
    global _jwks_client, _jwks_client_url
    if _jwks_client is None or _jwks_client_url != url:
        _jwks_client = jwt.PyJWKClient(url, cache_keys=True)
        _jwks_client_url = url
    return _jwks_client


# ── Token extraction ───────────────────────────────────────────────────────────

def _extract_bearer_token() -> str | None:
    """Return the bearer token from the Authorization header, or None."""
    header = request.headers.get("Authorization", "")
    if not header:
        return None
    parts = header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


# ── Core verification ───────────────────────────────────────────────────────────

def verify_supabase_jwt(token: str) -> dict:
    """
    Verify a Supabase access token and return its decoded claims.

    Signature scheme is auto-detected from the token's ``alg`` header:
      - HS256        → verified with SUPABASE_JWT_SECRET.
      - ES256/RS256  → verified with the project's JWKS public keys.

    Raises:
        AuthError: on any verification failure (missing config, bad signature,
                   expired, wrong audience, malformed token, …).
    """
    if not token:
        raise AuthError("Missing bearer token")

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise AuthError("Malformed token", detail=str(exc)) from exc

    alg = (header.get("alg") or "").upper()
    audience = _expected_audience()
    leeway = _leeway_seconds()
    # Supabase always sets exp + sub on access tokens; require both.
    options = {"require": ["exp", "sub"]}

    try:
        if alg == "HS256":
            secret = _jwt_secret()
            if not secret:
                raise AuthError(
                    "Supabase verification is not configured",
                    detail="SUPABASE_JWT_SECRET is required to verify HS256 tokens.",
                )
            claims = jwt.decode(
                token,
                secret,
                algorithms=["HS256"],
                audience=audience,
                leeway=leeway,
                options=options,
            )
        elif alg in ("ES256", "RS256"):
            jwks_url = _jwks_url()
            if not jwks_url:
                raise AuthError(
                    "Supabase verification is not configured",
                    detail="SUPABASE_URL or SUPABASE_JWKS_URL is required to verify asymmetric tokens.",
                )
            signing_key = _get_jwks_client(jwks_url).get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["ES256", "RS256"],
                audience=audience,
                leeway=leeway,
                options=options,
            )
        else:
            raise AuthError("Unsupported token algorithm", detail=f"alg={alg!r}")

    except AuthError:
        raise
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Token expired", detail=str(exc)) from exc
    except jwt.InvalidAudienceError as exc:
        raise AuthError("Invalid token audience", detail=str(exc)) from exc
    except jwt.PyJWKClientError as exc:
        raise AuthError("Could not resolve Supabase signing key", detail=str(exc)) from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Invalid token", detail=str(exc)) from exc
    except Exception as exc:  # network errors fetching JWKS, etc. — fail closed
        log.warning("Supabase JWT verification error: %s", exc)
        raise AuthError("Token verification failed", detail=str(exc)) from exc

    if not claims.get("sub"):
        raise AuthError("Token missing subject (sub) claim")

    return claims


# ── Artisan lookup ──────────────────────────────────────────────────────────────

# Safe, non-sensitive columns only. Key material (enc_private_key, key_nonce) is
# never loaded into the request context.
_ARTISAN_SAFE_COLUMNS = (
    "id, artisan_id, did, name, craft_type, cluster, location, "
    "algorand_wallet, ed25519_pubkey, status, supabase_id, email, "
    "profile_completed, approved_at, created_at"
)


def load_artisan_by_supabase_id(supabase_id: str) -> dict | None:
    """Return the artisan row (safe columns only) for a Supabase user id, or None."""
    conn = get_db_connection()
    cur = dict_cursor(conn)
    try:
        cur.execute(
            f"SELECT {_ARTISAN_SAFE_COLUMNS} FROM artisans WHERE supabase_id = %s",
            (supabase_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        cur.close()
        conn.close()


# ── Decorators ──────────────────────────────────────────────────────────────────

def _unauthorized(message: str, detail: str | None = None):
    payload = {"error": "Unauthorized", "message": message}
    if detail:
        payload["detail"] = detail
    return jsonify(payload), 401


def require_supabase_auth(fn):
    """
    Verify the Supabase JWT and attach the identity to ``flask.g``.

    On success, the wrapped view can read:
        g.supabase_claims  — full decoded JWT claims
        g.supabase_id      — the user's Supabase id (sub claim)
        g.artisan          — the matching artisans row (dict) or None if not yet
                             registered

    Returns HTTP 401 for any missing/invalid/expired token. An authenticated user
    WITHOUT an artisan profile is allowed through (g.artisan is None) — useful for
    the registration / onboarding endpoint.

    CORS preflight (OPTIONS) requests are passed through untouched.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return current_app.make_default_options_response()

        token = _extract_bearer_token()
        if not token:
            return _unauthorized("Missing or malformed Authorization header")

        try:
            claims = verify_supabase_jwt(token)
        except AuthError as exc:
            return _unauthorized(exc.message, exc.detail)

        supabase_id = claims["sub"]
        g.supabase_claims = claims
        g.supabase_id = supabase_id
        try:
            g.artisan = load_artisan_by_supabase_id(supabase_id)
        except Exception as exc:
            log.error("Artisan lookup failed for supabase_id=%s: %s", supabase_id, exc)
            g.artisan = None

        return fn(*args, **kwargs)

    return wrapper


def require_artisan_auth(fn):
    """
    Like :func:`require_supabase_auth`, but additionally requires that an artisan
    profile already exists for the authenticated Supabase user.

      - 401 if the token is missing/invalid/expired.
      - 404 if the token is valid but no artisan profile exists yet.

    On success, ``g.artisan`` is guaranteed to be a non-empty dict.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return current_app.make_default_options_response()

        token = _extract_bearer_token()
        if not token:
            return _unauthorized("Missing or malformed Authorization header")

        try:
            claims = verify_supabase_jwt(token)
        except AuthError as exc:
            return _unauthorized(exc.message, exc.detail)

        supabase_id = claims["sub"]
        g.supabase_claims = claims
        g.supabase_id = supabase_id

        try:
            artisan = load_artisan_by_supabase_id(supabase_id)
        except Exception as exc:
            log.error("Artisan lookup failed for supabase_id=%s: %s", supabase_id, exc)
            return jsonify({"error": "Profile lookup failed"}), 500

        if not artisan:
            return (
                jsonify(
                    {
                        "error": "Profile not found",
                        "message": "Authenticated, but no artisan profile is linked to this account yet.",
                        "supabase_id": supabase_id,
                    }
                ),
                404,
            )

        g.artisan = artisan
        return fn(*args, **kwargs)

    return wrapper
