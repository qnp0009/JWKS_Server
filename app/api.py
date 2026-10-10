"""HTTP routes for JWKS publication, token issuance, and key administration."""

from __future__ import annotations

import hmac
import json
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.keys import KeyManager
from app.models import (
    CreateKeyRequest,
    IssueTokenRequest,
    JWKSResponse,
    KeyMetadata,
    KeyNotFoundError,
    KeySelectionError,
    NoActiveKeyError,
    TokenRequestError,
    TokenResponse,
)
from app.tokens import resolve_sign_mode, sign_token

# RFC 7517 section 8.5. application/json is also widely accepted; this is the
# registered media type for a JSON Web Key Set.
JWKS_MEDIA_TYPE = "application/jwk-set+json"
_ISSUE_FIELDS = frozenset(
    {
        "sub",
        "username",
        "aud",
        "expired",
        "kid",
        "key_state",
        "use_inactive",
        "use_expired_key",
        "ttl_seconds",
        "claims",
    }
)

public_router = APIRouter(tags=["jwks"])
token_router = APIRouter(tags=["tokens"])
admin_router = APIRouter(tags=["keys"])


def get_manager(request: Request) -> KeyManager:
    return request.app.state.manager


def require_admin(
    request: Request,
    x_admin_key: Annotated[str | None, Header()] = None,
) -> None:
    """Enforce ``X-Admin-Key`` when ``JWKS_ADMIN_API_KEY`` is configured.

    An empty configured secret leaves the routes open for local development.
    """
    expected = request.app.state.settings.admin_api_key
    if not expected:
        return
    supplied = x_admin_key or ""
    if not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid or missing admin API key")


@public_router.get("/health")
def health(manager: KeyManager = Depends(get_manager)) -> JSONResponse:
    count = manager.active_count()
    body = {"status": "ok" if count else "degraded", "active_keys": count}
    status_code = 200 if count else 503
    return JSONResponse(status_code=status_code, content=body)


@public_router.get("/.well-known/jwks.json", response_model=JWKSResponse)
@public_router.get("/jwks.json", response_model=JWKSResponse)
def read_jwks(manager: KeyManager = Depends(get_manager)) -> JSONResponse:
    """Active public keys only. Pending, expired, and revoked keys are omitted."""
    return JSONResponse(
        content=manager.jwks(),
        media_type=JWKS_MEDIA_TYPE,
        headers={"Cache-Control": "public, max-age=60"},
    )


@token_router.post("/auth", response_model=TokenResponse, summary="Issue a signed JWT")
@token_router.post("/sign", response_model=TokenResponse, summary="Issue a signed JWT")
async def issue_token(
    request: Request,
    manager: KeyManager = Depends(get_manager),
    _: None = Depends(require_admin),
    expired: Annotated[
        bool | None,
        Query(description="When true, exp is already in the past. The signature stays valid."),
    ] = None,
    kid: Annotated[str | None, Query(description="Sign with this key id, including a pending or expired key.")] = None,
    key_state: Annotated[
        Literal["active", "inactive", "pending", "expired"] | None,
        Query(description="active (default), inactive / pending, or expired. Selects the signing key."),
    ] = None,
    use_inactive: Annotated[bool | None, Query(description="Sign with a key that is not active yet.")] = None,
    use_expired_key: Annotated[bool | None, Query(description="Sign with a key that has already expired.")] = None,
    sub: Annotated[str | None, Query(description="JWT subject. Defaults to test-user.")] = None,
    username: Annotated[str | None, Query(description="Alias of sub.")] = None,
    aud: Annotated[str | None, Query(description="Optional JWT audience.")] = None,
    ttl_seconds: Annotated[int | None, Query(gt=0, le=30 * 24 * 60 * 60)] = None,
) -> TokenResponse:
    """Issue an RS256 JWT.

    Parameters may be sent as a query string, a JSON object, or both. Body
    fields override query fields. ``expired=true`` makes the token itself
    expired. ``use_inactive``, ``use_expired_key``, and ``key_state`` choose
    a signing key that resource servers will not find in JWKS.
    """
    spec = await _read_issue_spec(
        request,
        {
            "expired": expired,
            "kid": kid,
            "key_state": key_state,
            "use_inactive": use_inactive,
            "use_expired_key": use_expired_key,
            "sub": sub,
            "username": username,
            "aud": aud,
            "ttl_seconds": ttl_seconds,
        },
    )
    try:
        selected_kid, mode = resolve_sign_mode(spec)
        record = manager.select_signing_key(kid=selected_kid, mode=mode)
        return sign_token(record, spec, request.app.state.settings)
    except KeyNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except NoActiveKeyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (KeySelectionError, TokenRequestError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@admin_router.get("/keys", response_model=list[KeyMetadata])
def list_keys(
    manager: KeyManager = Depends(get_manager),
    _: None = Depends(require_admin),
) -> list[KeyMetadata]:
    return manager.list_metadata()


@admin_router.post("/keys", response_model=KeyMetadata, status_code=201)
def create_key(
    payload: CreateKeyRequest | None = None,
    manager: KeyManager = Depends(get_manager),
    _: None = Depends(require_admin),
) -> KeyMetadata:
    payload = payload or CreateKeyRequest()
    try:
        record = manager.create_key(
            not_before=payload.not_before,
            expires_at=payload.expires_at,
            lifetime_seconds=payload.lifetime_seconds,
        )
    except KeySelectionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return manager.get_metadata(record.kid)


@admin_router.post("/keys/rotate", response_model=KeyMetadata, status_code=201)
def rotate_keys(
    manager: KeyManager = Depends(get_manager),
    _: None = Depends(require_admin),
) -> KeyMetadata:
    record = manager.rotate()
    return manager.get_metadata(record.kid)


@admin_router.get("/keys/{kid}", response_model=KeyMetadata)
def get_key(
    kid: str,
    manager: KeyManager = Depends(get_manager),
    _: None = Depends(require_admin),
) -> KeyMetadata:
    try:
        return manager.get_metadata(kid)
    except KeyNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@admin_router.post("/keys/{kid}/revoke", response_model=KeyMetadata)
def revoke_key(
    kid: str,
    manager: KeyManager = Depends(get_manager),
    _: None = Depends(require_admin),
) -> KeyMetadata:
    try:
        record = manager.revoke(kid)
    except KeyNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return manager.get_metadata(record.kid)


async def _read_issue_spec(request: Request, query_values: dict[str, Any]) -> IssueTokenRequest:
    merged: dict[str, Any] = {key: value for key, value in query_values.items() if value is not None}
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type.lower():
        raw = await request.body()
        if raw.strip():
            try:
                body = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=400, detail="Request body is not valid JSON") from exc
            if not isinstance(body, dict):
                raise HTTPException(status_code=400, detail="JSON body must be an object")
            unknown = sorted(set(body) - _ISSUE_FIELDS)
            if unknown:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unknown fields: {', '.join(unknown)}",
                )
            for key, value in body.items():
                if value is not None:
                    merged[key] = value
    try:
        return IssueTokenRequest.model_validate(merged)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc
