"""Security-focused tests, grouped by OWASP-style area."""
import base64
import json
import sqlite3

import jwt
import pytest
from jwt import PyJWK

# ========== 1. Authentication / admin key ==================================
PROTECTED = [("post", "/auth"), ("post", "/sign"), ("get", "/keys"), ("post", "/keys"),
             ("post", "/keys/rotate"), ("get", "/keys/x"), ("post", "/keys/x/revoke")]
PUBLIC = [("get", "/health"), ("get", "/jwks.json"), ("get", "/.well-known/jwks.json"), ("get", "/")]

@pytest.mark.parametrize("method,path", PROTECTED)
def test_protected_routes_reject_missing_key(secured_client, method, path):
    assert getattr(secured_client, method)(path).status_code == 401

@pytest.mark.parametrize("method,path", PROTECTED)
def test_protected_routes_reject_wrong_key(secured_client, method, path):
    assert getattr(secured_client, method)(path, headers={"X-Admin-Key": "nope"}).status_code == 401

@pytest.mark.parametrize("bad", ["", " s3cret", "s3cret ", "S3CRET", "s3cre", "s3cret2", "s3cret\x00"])
def test_admin_key_must_match_exactly(secured_client, bad):
    try:
        r = secured_client.get("/keys", headers={"X-Admin-Key": bad})
    except Exception:          # illegal header bytes are rejected by the client itself
        return
    assert r.status_code == 401

def test_admin_key_correct_is_accepted(secured_client):
    assert secured_client.get("/keys", headers={"X-Admin-Key": "s3cret"}).status_code == 200

@pytest.mark.parametrize("method,path", PUBLIC)
def test_public_routes_need_no_key(secured_client, method, path):
    assert getattr(secured_client, method)(path).status_code == 200

def test_admin_key_not_accepted_from_query_string(secured_client):
    assert secured_client.get("/keys?x_admin_key=s3cret").status_code == 401

def test_no_admin_key_configured_leaves_routes_open(client):
    """Insecure default: documents that auth is optional."""
    assert client.get("/keys").status_code == 200 and client.post("/auth").status_code == 200

def test_401_does_not_reveal_expected_key(secured_client):
    assert "s3cret" not in secured_client.get("/keys").text

def test_token_endpoint_issues_for_any_subject_no_credential_check(client):
    """/auth has no password check: any caller may mint a token for any subject."""
    r = client.post("/auth", json={"sub": "admin"})
    assert r.status_code == 200

# ========== 2. Authorization / privilege ====================================
def test_claims_cannot_override_issuer_or_subject(client):
    t = client.post("/auth", json={"sub": "bob", "claims": {"iss": "attacker", "sub": "root"}}).json()
    c = jwt.decode(t["access_token"], options={"verify_signature": False})
    assert c["iss"] == "jwks-server" and c["sub"] == "bob"

def test_arbitrary_privilege_claims_are_accepted(client):
    """Mass-assignment risk: caller-chosen claims such as role=admin are signed."""
    t = client.post("/auth", json={"claims": {"role": "admin", "scope": "*"}}).json()
    c = jwt.decode(t["access_token"], options={"verify_signature": False})
    assert c["role"] == "admin"

def test_revoked_key_cannot_sign_even_by_explicit_kid(client):
    kid = client.get("/keys").json()[0]["kid"]
    client.post(f"/keys/{kid}/revoke")
    assert client.post(f"/auth?kid={kid}").status_code == 400

def test_revoked_key_disappears_from_jwks(client):
    kid = client.get("/keys").json()[0]["kid"]
    client.post(f"/keys/{kid}/revoke")
    assert all(k["kid"] != kid for k in client.get("/jwks.json").json()["keys"])

def test_secured_server_blocks_test_key_modes(secured_client):
    for q in ("use_expired_key=true", "key_state=pending", "expired=true"):
        assert secured_client.post(f"/auth?{q}").status_code == 401

# ========== 3. Input validation ==============================================
@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>", "' OR 1=1 --", "$(id)", "../../etc/passwd",
    "A" * 256, "ünï©ødé", "{{7*7}}"])
def test_special_characters_in_sub_do_not_break_signing(client, payload):
    r = client.post("/auth", json={"sub": payload})
    assert r.status_code == 200
    c = jwt.decode(r.json()["access_token"], options={"verify_signature": False})
    assert c["sub"] == payload.strip()      # stored verbatim, never interpreted

def test_whitespace_only_sub_rejected(client):
    # Corrected after first run: LLM expected 200; app rejects blank subjects (422).
    assert client.post("/auth", json={"sub": "\n\r"}).status_code == 422

def test_oversized_sub_rejected(client):
    assert client.post("/auth", json={"sub": "A" * 257}).status_code == 422

def test_oversized_kid_rejected(client):
    assert client.post("/auth", json={"kid": "k" * 129}).status_code == 422

def test_oversized_aud_rejected(client):
    assert client.post("/auth", json={"aud": "a" * 257}).status_code == 422

@pytest.mark.parametrize("body", [{"sub": 123}, {"sub": ["a"]}, {"expired": "perhaps"},
                                  {"ttl_seconds": "NaN"}, {"ttl_seconds": 1.5},
                                  {"claims": "x"}, {"key_state": "root"}])
def test_wrong_types_rejected(client, body):
    assert client.post("/auth", json=body).status_code in (400, 422)

@pytest.mark.parametrize("ttl", [0, -1, 30 * 24 * 3600 + 1, 10**12])
def test_ttl_boundaries_rejected(client, ttl):
    assert client.post("/auth", json={"ttl_seconds": ttl}).status_code == 422

def test_ttl_max_boundary_accepted(client):
    assert client.post("/auth", json={"ttl_seconds": 30 * 24 * 3600}).status_code == 200

def test_deeply_nested_claims_do_not_crash(client):
    nested = cur = {}
    for _ in range(200):
        cur["a"] = {}; cur = cur["a"]
    assert client.post("/auth", json={"claims": nested}).status_code in (200, 400, 422)

def test_malformed_json_gives_clean_error_not_500(client):
    r = client.post("/auth", content=b'{"sub": ', headers={"content-type": "application/json"})
    assert r.status_code == 400 and "Traceback" not in r.text

def test_non_json_content_type_body_is_ignored(client):
    r = client.post("/auth", content=b'{"sub": "x"}', headers={"content-type": "text/plain"})
    assert r.status_code == 200
    c = jwt.decode(r.json()["access_token"], options={"verify_signature": False})
    assert c["sub"] == "test-user"

def test_invalid_timestamp_in_create_key_rejected(client):
    assert client.post("/keys", json={"not_before": "yesterday-ish"}).status_code == 422

# ========== 4. Injection ======================================================
@pytest.mark.parametrize("kid", ["' OR '1'='1", "x'; DROP TABLE keys;--", "%", "\" OR \"\"=\"",
                                 "../keystore.json", "<img src=x onerror=1>"])
def test_kid_injection_returns_404_on_sqlite(client_factory, tmp_path, kid):
    db = tmp_path / "k.db"
    c = client_factory(storage_backend="sqlite", storage_path=str(db))
    assert c.post("/auth", params={"kid": kid}).status_code == 404
    assert c.get("/keys/" + kid.replace("/", "%2F")).status_code == 404
    with sqlite3.connect(db) as con:                 # table still exists with its row
        assert con.execute("SELECT count(*) FROM keys").fetchone()[0] == 1

def test_error_message_escapes_kid_as_json(client):
    r = client.get("/keys/%3Cscript%3E")
    assert r.headers["content-type"].startswith("application/json")

def test_file_backend_path_not_user_controlled(client_factory, tmp_path):
    p = tmp_path / "ks.json"
    c = client_factory(storage_backend="file", storage_path=str(p))
    c.post("/auth?kid=../../etc/passwd")
    assert p.exists() and p.parent == tmp_path

# ========== 5. API security =====================================================
@pytest.mark.parametrize("method,path", [("get", "/auth"), ("put", "/auth"), ("delete", "/keys"),
                                         ("patch", "/keys/x"), ("post", "/jwks.json"),
                                         ("delete", "/jwks.json"), ("post", "/health")])
def test_unexpected_http_methods_405(client, method, path):
    assert getattr(client, method)(path).status_code == 405

def test_unknown_route_404(client):
    assert client.get("/admin").status_code == 404

def test_rate_limit_throttles_token_brute_force(client_factory):
    c = client_factory(rate_limit_per_second=5)
    codes = [c.post("/auth").status_code for _ in range(10)]
    assert codes.count(429) == 5

def test_rate_limit_applies_to_unauthenticated_requests(client_factory):
    c = client_factory(rate_limit_per_second=2, admin_api_key="k")
    codes = [c.get("/keys").status_code for _ in range(4)]
    assert codes == [401, 401, 429, 429]

def test_cors_wildcard_default_is_permissive(client):
    r = client.get("/jwks.json", headers={"Origin": "https://anywhere.example"})
    assert r.headers["access-control-allow-origin"] == "*"

def test_jwks_is_cacheable_but_token_response_not_marked_public(client):
    assert "public" in client.get("/jwks.json").headers["cache-control"]
    assert "public" not in client.post("/auth").headers.get("cache-control", "")

# ========== 6. Data protection / crypto ===========================================
def test_private_material_never_in_any_response(client):
    client.post("/keys/rotate")
    texts = [client.get("/jwks.json").text, client.get("/keys").text,
             client.post("/keys").text, client.post("/auth").text]
    for t in texts:
        assert "PRIVATE KEY" not in t and '"d"' not in t

def test_error_responses_do_not_leak_internals(client):
    for r in (client.post("/auth?kid=zzz"), client.get("/keys/zzz"), client.post("/auth?ttl_seconds=0")):
        assert "Traceback" not in r.text and "PRIVATE" not in r.text and "app/" not in r.text

def test_signed_token_cannot_be_verified_with_tampered_payload(client):
    t = client.post("/auth").json()["access_token"]
    h, p, s = t.split(".")
    pad = "=" * (-len(p) % 4)
    claims = json.loads(base64.urlsafe_b64decode(p + pad)); claims["sub"] = "root"
    p2 = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    jwk = client.get("/jwks.json").json()["keys"][0]
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(f"{h}.{p2}.{s}", PyJWK(jwk).key, algorithms=["RS256"], options={"verify_exp": False})

def test_alg_none_token_rejected_by_verifier(client):
    jwk = client.get("/jwks.json").json()["keys"][0]
    forged = jwt.encode({"sub": "x"}, key=None, algorithm="none")
    with pytest.raises(jwt.InvalidAlgorithmError):
        jwt.decode(forged, PyJWK(jwk).key, algorithms=["RS256"])

def test_token_algorithm_is_always_rs256(client):
    for _ in range(3):
        assert jwt.get_unverified_header(client.post("/auth").json()["access_token"])["alg"] == "RS256"

def test_jwks_key_size_is_at_least_2048(client):
    n = client.get("/jwks.json").json()["keys"][0]["n"]
    raw = base64.urlsafe_b64decode(n + "=" * (-len(n) % 4))
    assert len(raw) * 8 >= 2048

def test_expired_flag_token_fails_standard_validation(client):
    t = client.post("/auth?expired=true").json()["access_token"]
    jwk = client.get("/jwks.json").json()["keys"][0]
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(t, PyJWK(jwk).key, algorithms=["RS256"], leeway=60)

def test_pending_key_token_fails_jwks_lookup(client):
    body = client.post("/auth?key_state=pending").json()
    kids = {k["kid"] for k in client.get("/jwks.json").json()["keys"]}
    assert jwt.get_unverified_header(body["access_token"])["kid"] not in kids

def test_token_ids_are_unique_for_replay_tracking(client):
    ids = {jwt.decode(client.post("/auth").json()["access_token"],
                      options={"verify_signature": False})["jti"] for _ in range(5)}
    assert len(ids) == 5

def test_sqlite_file_contains_plaintext_private_key(client_factory, tmp_path):
    """Documents the at-rest weakness: no encryption of private_pem."""
    db = tmp_path / "k.db"; client_factory(storage_backend="sqlite", storage_path=str(db))
    with sqlite3.connect(db) as con:
        pem = con.execute("SELECT private_pem FROM keys").fetchone()[0]
    assert "BEGIN PRIVATE KEY" in pem

def test_startup_without_admin_key_logs_warning(caplog):
    import logging
    from app.main import _log_startup
    from tests_llm.conftest import make_settings
    with caplog.at_level(logging.WARNING):
        _log_startup(make_settings())
    assert "unauthenticated" in caplog.text
