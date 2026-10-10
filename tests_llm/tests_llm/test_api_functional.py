"""Functional black/white-box tests for HTTP routes."""
import jwt
import pytest
from jwt import PyJWK

def verify(client, token, **kw):
    header = jwt.get_unverified_header(token)
    jwk = next(k for k in client.get("/jwks.json").json()["keys"] if k["kid"] == header["kid"])
    return jwt.decode(token, PyJWK(jwk).key, algorithms=["RS256"], **kw)


def test_root_lists_endpoints(client):
    body = client.get("/").json()
    assert body["jwks_uri"] == "/.well-known/jwks.json" and body["token_endpoint"] == "/auth"

def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok", "active_keys": 1}

def test_health_degraded_when_no_active_key(client):
    for k in client.get("/keys").json():
        client.post(f"/keys/{k['kid']}/revoke")
    r = client.get("/health")
    assert r.status_code == 503 and r.json()["status"] == "degraded"

@pytest.mark.parametrize("path", ["/jwks.json", "/.well-known/jwks.json"])
def test_jwks_both_paths(client, path):
    r = client.get(path)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/jwk-set+json")
    assert r.headers["cache-control"] == "public, max-age=60"
    key = r.json()["keys"][0]
    assert key["kty"] == "RSA" and key["alg"] == "RS256" and key["use"] == "sig"

def test_jwks_exposes_no_private_members(client):
    key = client.get("/jwks.json").json()["keys"][0]
    assert not ({"d", "p", "q", "dp", "dq", "qi"} & set(key))

@pytest.mark.parametrize("path", ["/auth", "/sign"])
def test_issue_token_default_valid_and_verifiable(client, path):
    r = client.post(path)
    assert r.status_code == 200
    body = r.json()
    claims = verify(client, body["access_token"], issuer="jwks-server")
    assert claims["sub"] == "test-user"
    assert body["token_type"] == "Bearer" and body["key_status"] == "active"
    assert body["expires_in"] == 3600 and body["expired"] is False

def test_header_has_kid_and_typ(client):
    h = jwt.get_unverified_header(client.post("/auth").json()["access_token"])
    assert h["typ"] == "JWT" and h["alg"] == "RS256" and h["kid"].startswith("key-")

def test_username_alias_and_sub(client):
    t = client.post("/auth?username=alice").json()["access_token"]
    assert verify(client, t)["sub"] == "alice"

def test_audience_claim(client):
    t = client.post("/auth?aud=api").json()["access_token"]
    assert verify(client, t, audience="api")["aud"] == "api"

def test_custom_ttl(client):
    assert client.post("/auth?ttl_seconds=120").json()["expires_in"] == 120

def test_expired_token_flag(client):
    body = client.post("/auth?expired=true").json()
    assert body["expired"] is True and body["expires_in"] < 0
    with pytest.raises(jwt.ExpiredSignatureError):
        verify(client, body["access_token"])

def test_pending_key_token_not_verifiable_via_jwks(client):
    body = client.post("/auth?key_state=pending").json()
    assert body["key_status"] == "pending"
    kids = {k["kid"] for k in client.get("/jwks.json").json()["keys"]}
    assert body["kid"] not in kids

def test_expired_key_token(client):
    body = client.post("/auth?use_expired_key=true").json()
    assert body["key_status"] == "expired"

def test_use_inactive_flag(client):
    assert client.post("/auth?use_inactive=true").json()["key_status"] == "pending"

def test_explicit_kid(client):
    kid = client.get("/keys").json()[0]["kid"]
    assert client.post(f"/auth?kid={kid}").json()["kid"] == kid

def test_json_body_overrides_query(client):
    r = client.post("/auth?sub=query", json={"sub": "body"})
    assert verify(client, r.json()["access_token"])["sub"] == "body"

def test_json_body_null_values_ignored(client):
    r = client.post("/auth", json={"sub": None})
    assert r.status_code == 200

def test_empty_json_body_ok(client):
    r = client.post("/auth", content=b"  ", headers={"content-type": "application/json"})
    assert r.status_code == 200

def test_custom_claims_included_reserved_ignored(client):
    r = client.post("/auth", json={"claims": {"role": "x", "iss": "evil", "exp": 1}})
    c = verify(client, r.json()["access_token"], issuer="jwks-server")
    assert c["role"] == "x" and c["exp"] > 1000

# ---- error paths ---------------------------------------------------------
def test_invalid_json_400(client):
    r = client.post("/auth", content=b"{bad", headers={"content-type": "application/json"})
    assert r.status_code == 400

def test_json_array_body_400(client):
    assert client.post("/auth", json=[1]).status_code == 400

def test_unknown_field_400(client):
    r = client.post("/auth", json={"admin": True})
    assert r.status_code == 400 and "admin" in r.json()["detail"]

def test_unknown_kid_404(client):
    assert client.post("/auth?kid=missing").status_code == 404

def test_revoked_kid_400(client):
    kid = client.get("/keys").json()[0]["kid"]
    client.post(f"/keys/{kid}/revoke")
    assert client.post(f"/auth?kid={kid}").status_code == 400

def test_no_active_key_503(client):
    for k in client.get("/keys").json():
        client.post(f"/keys/{k['kid']}/revoke")
    assert client.post("/auth").status_code == 503

def test_conflicting_key_modes_400(client):
    assert client.post("/auth?use_inactive=true&use_expired_key=true").status_code == 400

def test_kid_with_inactive_400(client):
    assert client.post("/auth?kid=x&use_inactive=true").status_code == 400

def test_key_state_active_conflicts_with_use_inactive_400(client):
    assert client.post("/auth?key_state=active&use_inactive=true").status_code == 400

@pytest.mark.parametrize("q", ["ttl_seconds=0", "ttl_seconds=-5", "ttl_seconds=2592001",
                               "ttl_seconds=abc", "expired=maybe", "key_state=bogus"])
def test_invalid_query_422(client, q):
    assert client.post(f"/auth?{q}").status_code == 422

def test_blank_sub_422(client):
    assert client.post("/auth?sub=%20%20").status_code == 422

def test_sub_username_mismatch_is_client_error(client):
    r = client.post("/auth?sub=a&username=b")
    assert r.status_code == 422, r.text

def test_claims_not_object_422(client):
    assert client.post("/auth", json={"claims": [1]}).status_code == 422

def test_claims_too_large_400(client):
    r = client.post("/auth", json={"claims": {"x": "a" * 9000}})
    assert r.status_code == 400

# ---- key admin routes ------------------------------------------------------
def test_list_keys(client):
    assert len(client.get("/keys").json()) == 1

def test_create_key_no_body(client):
    r = client.post("/keys")
    assert r.status_code == 201 and r.json()["status"] == "active"

def test_create_key_future_is_pending(client):
    r = client.post("/keys", json={"not_before": "2999-01-01T00:00:00Z"})
    assert r.json()["status"] == "pending"

def test_create_key_past_is_expired(client):
    r = client.post("/keys", json={"expires_at": "2000-01-01T00:00:00Z"})
    assert r.json()["status"] == "expired"

def test_create_key_bad_window_400(client):
    r = client.post("/keys", json={"not_before": "2030-01-02T00:00:00Z",
                                   "expires_at": "2030-01-01T00:00:00Z"})
    assert r.status_code == 400

def test_create_key_invalid_lifetime_422(client):
    assert client.post("/keys", json={"lifetime_seconds": 0}).status_code == 422

def test_rotate_route(client):
    assert client.post("/keys/rotate").status_code == 201
    assert len(client.get("/jwks.json").json()["keys"]) == 2

def test_get_key_and_404(client):
    kid = client.get("/keys").json()[0]["kid"]
    assert client.get(f"/keys/{kid}").json()["kid"] == kid
    assert client.get("/keys/nope").status_code == 404

def test_revoke_route_and_404(client):
    kid = client.get("/keys").json()[0]["kid"]
    r = client.post(f"/keys/{kid}/revoke")
    assert r.json()["revoked"] is True and r.json()["status"] == "revoked"
    assert client.post("/keys/nope/revoke").status_code == 404
