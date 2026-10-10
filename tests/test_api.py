"""HTTP contract for JWKS publication and JWT issuance."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient
from jwt import PyJWK

from app.api import JWKS_MEDIA_TYPE
from app.main import create_app
from tests.helpers import make_settings, open_client


def _kids(document: dict) -> set[str]:
    return {item["kid"] for item in document["keys"]}


def _decode(token: str, jwk: dict, **kwargs: object) -> dict:
    key = PyJWK.from_dict(jwk).key
    return jwt.decode(token, key, algorithms=["RS256"], **kwargs)


def test_service_index_and_health(client: TestClient) -> None:
    assert client.get("/").json()["jwks_uri"] == "/.well-known/jwks.json"
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok", "active_keys": 1}


def test_jwks_document_lists_the_active_public_key(client: TestClient) -> None:
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(JWKS_MEDIA_TYPE)
    assert response.headers["cache-control"] == "public, max-age=60"
    document = response.json()
    assert len(document["keys"]) == 1
    jwk = document["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert jwk["e"] == "AQAB"
    assert "PRIVATE" not in response.text
    alias = client.get("/jwks.json")
    assert _kids(alias.json()) == _kids(document)


def test_resource_server_verifies_a_token_from_jwks(client: TestClient) -> None:
    issued = client.post("/sign", json={"sub": "service-a", "aud": "orders", "ttl_seconds": 30}).json()
    assert issued["token_type"] == "Bearer"
    assert issued["alg"] == "RS256"
    assert issued["expired"] is False
    assert issued["expires_in"] == 30
    assert issued["key_status"] == "active"
    header = jwt.get_unverified_header(issued["access_token"])
    assert header["kid"] == issued["kid"]
    assert header["alg"] == "RS256"
    assert header["typ"] == "JWT"
    document = client.get("/.well-known/jwks.json").json()
    claims = _decode(
        issued["access_token"],
        next(item for item in document["keys"] if item["kid"] == header["kid"]),
        audience="orders",
    )
    assert claims["sub"] == "service-a"
    assert claims["iss"] == "jwks-server"
    assert claims["aud"] == "orders"


def test_expired_query_keeps_a_valid_signature(client: TestClient) -> None:
    issued = client.post("/auth", params={"expired": "true", "sub": "qa"}).json()
    assert issued["expired"] is True
    assert issued["expires_in"] == -120
    assert issued["key_status"] == "active"
    assert issued["exp"] < int(time.time())
    document = client.get("/.well-known/jwks.json").json()
    jwk = next(item for item in document["keys"] if item["kid"] == issued["kid"])
    with pytest.raises(jwt.ExpiredSignatureError):
        _decode(issued["access_token"], jwk)
    claims = _decode(issued["access_token"], jwk, options={"verify_exp": False})
    assert claims["sub"] == "qa"
    assert claims["exp"] == issued["exp"]


def test_json_body_overrides_the_query_string(client: TestClient) -> None:
    issued = client.post("/auth", params={"expired": "true"}, json={"expired": False, "username": "bob"}).json()
    assert issued["expired"] is False
    assert issued["expires_in"] == 900
    document = client.get("/.well-known/jwks.json").json()
    jwk = next(item for item in document["keys"] if item["kid"] == issued["kid"])
    claims = _decode(issued["access_token"], jwk)
    assert claims["sub"] == "bob"


def test_extra_claims_cannot_replace_registered_claims(client: TestClient) -> None:
    issued = client.post("/auth", json={"claims": {"role": "admin", "iss": "evil"}}).json()
    document = client.get("/.well-known/jwks.json").json()
    jwk = next(item for item in document["keys"] if item["kid"] == issued["kid"])
    claims = _decode(issued["access_token"], jwk)
    assert claims["role"] == "admin"
    assert claims["iss"] == "jwks-server"


def test_conflicting_key_selection_is_rejected(client: TestClient) -> None:
    response = client.post("/auth", json={"use_inactive": True, "use_expired_key": True})
    assert response.status_code == 400
    response = client.post("/auth", params={"kid": "key-missing", "key_state": "inactive"})
    assert response.status_code == 400
    response = client.post("/auth", json={"kid": "key-does-not-exist"})
    assert response.status_code == 404
    response = client.post("/keys", json={"not_before": "2026-02-01T00:00:00Z", "expires_at": "2026-01-01T00:00:00Z"})
    assert response.status_code == 400


def test_inactive_key_is_omitted_from_jwks_and_reused(fresh_client: TestClient) -> None:
    first = fresh_client.post("/auth", json={"use_inactive": True}).json()
    second = fresh_client.post("/auth", params={"key_state": "pending"}).json()
    assert first["key_status"] == "pending"
    assert second["kid"] == first["kid"]
    assert first["kid"] not in _kids(fresh_client.get("/.well-known/jwks.json").json())
    metadata = fresh_client.get(f"/keys/{first['kid']}").json()
    claims = _decode(first["access_token"], metadata["jwk"])
    assert claims["sub"] == "test-user"
    assert "PRIVATE" not in fresh_client.get("/keys").text


def test_expired_key_can_sign_a_token_that_jwks_will_not_verify(fresh_client: TestClient) -> None:
    issued = fresh_client.post(
        "/auth",
        json={"use_expired_key": True, "expired": True, "sub": "legacy"},
    ).json()
    assert issued["key_status"] == "expired"
    assert issued["expired"] is True
    assert issued["kid"] not in _kids(fresh_client.get("/.well-known/jwks.json").json())
    metadata = fresh_client.get(f"/keys/{issued['kid']}").json()
    claims = _decode(issued["access_token"], metadata["jwk"], options={"verify_exp": False})
    assert claims["sub"] == "legacy"
    assert claims["exp"] < int(time.time())


def test_explicit_kid_selects_a_pending_key(fresh_client: TestClient) -> None:
    not_before = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    created = fresh_client.post("/keys", json={"not_before": not_before}).json()
    assert created["status"] == "pending"
    issued = fresh_client.post("/sign", params={"kid": created["kid"]}).json()
    assert issued["kid"] == created["kid"]
    assert issued["key_status"] == "pending"
    assert issued["kid"] not in _kids(fresh_client.get("/jwks.json").json())


def test_rotation_publishes_a_new_key_and_keeps_the_old_one(fresh_client: TestClient) -> None:
    before = fresh_client.get("/.well-known/jwks.json").json()["keys"]
    rotated = fresh_client.post("/keys/rotate").json()
    after = fresh_client.get("/.well-known/jwks.json").json()["keys"]
    assert rotated["status"] == "active"
    assert after[0]["kid"] == rotated["kid"]
    assert {item["kid"] for item in before}.issubset(_kids({"keys": after}))
    issued = fresh_client.post("/auth").json()
    assert issued["kid"] == rotated["kid"]
    old = next(item for item in after if item["kid"] != rotated["kid"])
    previous = fresh_client.post("/auth", json={"kid": old["kid"]}).json()
    _decode(previous["access_token"], old)


def test_revoke_removes_the_key_and_blocks_signing(fresh_client: TestClient) -> None:
    active = next(item for item in fresh_client.get("/keys").json() if item["status"] == "active")
    revoked = fresh_client.post(f"/keys/{active['kid']}/revoke")
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert active["kid"] not in _kids(fresh_client.get("/.well-known/jwks.json").json())
    assert fresh_client.post("/auth", json={"kid": active["kid"]}).status_code == 400
    assert fresh_client.post("/auth").status_code == 503
    health = fresh_client.get("/health")
    assert health.status_code == 503
    assert health.json()["status"] == "degraded"
    assert fresh_client.post(f"/keys/{active['kid']}/revoke").json()["status"] == "revoked"


def test_jwks_stays_public_when_admin_key_is_required() -> None:
    with TestClient(create_app(make_settings())) as public:
        assert public.get("/.well-known/jwks.json").status_code == 200
        assert public.post("/auth", json={"sub": "x"}).status_code == 401
        assert public.get("/keys").status_code == 401
        assert public.post("/auth", headers={"X-Admin-Key": "wrong"}).status_code == 401
        allowed = public.post("/auth", headers={"X-Admin-Key": "test-admin"}, json={"sub": "ops"})
        assert allowed.status_code == 200
        assert allowed.json()["kid"]


def test_empty_admin_key_leaves_routes_open() -> None:
    client = open_client(make_settings(admin_api_key=""))
    try:
        assert client.post("/auth", json={"sub": "local"}).status_code == 200
        assert client.get("/keys").status_code == 200
    finally:
        client.__exit__(None, None, None)


@pytest.mark.parametrize("backend", ["file", "sqlite"])
def test_restart_keeps_the_published_key(tmp_path, backend: str) -> None:
    path = tmp_path / ("keystore.json" if backend == "file" else "keys.db")
    settings = make_settings(
        storage_backend=backend,
        storage_path=str(path),
        admin_api_key="",
    )
    first = open_client(settings)
    try:
        kid = first.get("/.well-known/jwks.json").json()["keys"][0]["kid"]
    finally:
        first.__exit__(None, None, None)
    second = open_client(settings)
    try:
        assert kid in _kids(second.get("/.well-known/jwks.json").json())
        issued = second.post("/auth").json()
        assert issued["kid"] == kid
    finally:
        second.__exit__(None, None, None)
