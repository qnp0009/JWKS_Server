"""JWT claim construction and RS256 signing."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

import jwt

from app.config import Settings
from app.models import (
    IssueTokenRequest,
    KeyRecord,
    KeySelectionError,
    SignKeyMode,
    TokenRequestError,
    TokenResponse,
)

logger = logging.getLogger(__name__)

# Far enough in the past to fail validators that allow about a minute of clock skew.
EXPIRED_TOKEN_OFFSET_SECONDS = 120
_MAX_CLAIMS_JSON_BYTES = 8192
_RESERVED_CLAIMS = frozenset({"iss", "sub", "iat", "nbf", "exp", "jti", "aud"})


def resolve_sign_mode(spec: IssueTokenRequest) -> tuple[str | None, SignKeyMode]:
    """Map the public test switches onto a single signing mode.

    ``expired`` is intentionally not read here. It changes the token's exp
    claim and does not choose the key.
    """
    requested: list[SignKeyMode] = []
    if spec.use_inactive:
        requested.append(SignKeyMode.INACTIVE)
    if spec.use_expired_key:
        requested.append(SignKeyMode.EXPIRED)
    if spec.key_state in {"inactive", "pending"}:
        requested.append(SignKeyMode.INACTIVE)
    elif spec.key_state == "expired":
        requested.append(SignKeyMode.EXPIRED)
    elif spec.key_state == "active" and (spec.use_inactive or spec.use_expired_key):
        raise KeySelectionError("key_state=active conflicts with an inactive or expired key request")

    unique = list(dict.fromkeys(requested))
    if len(unique) > 1:
        raise KeySelectionError("Request only one of an inactive key or an expired key")
    mode = unique[0] if unique else SignKeyMode.ACTIVE
    if spec.kid and mode is not SignKeyMode.ACTIVE:
        raise KeySelectionError("kid cannot be combined with an inactive or expired key request")
    return spec.kid, mode


def build_claims(spec: IssueTokenRequest, settings: Settings, now: datetime) -> dict[str, object]:
    """Build registered claims. Caller-supplied values cannot replace them."""
    extra = dict(spec.claims)
    for name in _RESERVED_CLAIMS:
        extra.pop(name, None)
    try:
        encoded = json.dumps(extra)
    except (TypeError, ValueError) as exc:
        raise TokenRequestError("claims must be JSON-serializable") from exc
    if len(encoded.encode("utf-8")) > _MAX_CLAIMS_JSON_BYTES:
        raise TokenRequestError("claims payload is too large")

    ttl = spec.ttl_seconds if spec.ttl_seconds is not None else settings.token_ttl_seconds
    if spec.expired:
        exp_at = now - timedelta(seconds=EXPIRED_TOKEN_OFFSET_SECONDS)
        iat_at = exp_at - timedelta(seconds=ttl)
    else:
        iat_at = now
        exp_at = now + timedelta(seconds=ttl)

    claims: dict[str, object] = {
        **extra,
        "iss": settings.issuer,
        "sub": spec.subject(),
        "iat": int(iat_at.timestamp()),
        "nbf": int(iat_at.timestamp()),
        "exp": int(exp_at.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    if spec.aud:
        claims["aud"] = spec.aud
    return claims


def sign_token(record: KeyRecord, spec: IssueTokenRequest, settings: Settings) -> TokenResponse:
    """Sign ``spec`` with ``record`` and describe the token that was produced."""
    now = datetime.now(timezone.utc)
    claims = build_claims(spec, settings, now)
    try:
        signed = jwt.encode(
            claims,
            record.private_pem,
            algorithm=record.alg,
            headers={"kid": record.kid, "typ": "JWT"},
        )
    except jwt.PyJWTError as exc:
        logger.exception("JWT signing failed kid=%s", record.kid)
        raise TokenRequestError("Unable to sign the token") from exc
    if isinstance(signed, bytes):
        signed = signed.decode("ascii")
    exp = int(claims["exp"])
    return TokenResponse(
        access_token=signed,
        expires_in=exp - int(now.timestamp()),
        expired=spec.expired,
        exp=exp,
        kid=record.kid,
        key_status=record.status_at(now),
        alg=record.alg,
    )
