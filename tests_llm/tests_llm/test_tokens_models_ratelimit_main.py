"""tokens.py, models.py parsing helpers, ratelimit.py, main.py, __main__.py."""
import asyncio
import logging
from datetime import datetime, timezone

import jwt
import pytest

import app.__main__ as entry
import app.tokens as tokens
from app.keys import KeyManager
from app.main import _log_startup, _rotation_loop, create_app
from app.models import (IssueTokenRequest, KeyRecord, KeySelectionError, SignKeyMode,
                        TokenRequestError, _parse_bool, _parse_datetime)
from app.ratelimit import RateLimitMiddleware, SlidingWindowLimiter
from app.stores import MemoryKeyStore
from tests_llm.conftest import _PAIR, make_settings

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
def spec(**kw): return IssueTokenRequest(**kw)

# ---- resolve_sign_mode: decision table ---------------------------------------
@pytest.mark.parametrize("kw,mode", [
    ({}, SignKeyMode.ACTIVE),
    ({"use_inactive": True}, SignKeyMode.INACTIVE),
    ({"use_expired_key": True}, SignKeyMode.EXPIRED),
    ({"key_state": "inactive"}, SignKeyMode.INACTIVE),
    ({"key_state": "pending"}, SignKeyMode.INACTIVE),
    ({"key_state": "expired"}, SignKeyMode.EXPIRED),
    ({"key_state": "active"}, SignKeyMode.ACTIVE),
    ({"use_inactive": True, "key_state": "pending"}, SignKeyMode.INACTIVE),  # duplicates collapse
])
def test_resolve_sign_mode_ok(kw, mode):
    assert tokens.resolve_sign_mode(spec(**kw)) == (None, mode)

@pytest.mark.parametrize("kw", [
    {"use_inactive": True, "use_expired_key": True},
    {"key_state": "expired", "use_inactive": True},
    {"key_state": "active", "use_expired_key": True},
    {"kid": "k", "use_inactive": True},
])
def test_resolve_sign_mode_conflicts(kw):
    with pytest.raises(KeySelectionError):
        tokens.resolve_sign_mode(spec(**kw))

def test_resolve_keeps_kid_for_active():
    assert tokens.resolve_sign_mode(spec(kid="k")) == ("k", SignKeyMode.ACTIVE)

# ---- build_claims -----------------------------------------------------------------
def test_build_claims_defaults():
    c = tokens.build_claims(spec(), make_settings(), NOW)
    assert c["exp"] - c["iat"] == 3600 and c["nbf"] == c["iat"] and c["sub"] == "test-user"
    assert "aud" not in c

def test_build_claims_expired_is_in_past():
    c = tokens.build_claims(spec(expired=True, ttl_seconds=10), make_settings(), NOW)
    assert c["exp"] == int(NOW.timestamp()) - tokens.EXPIRED_TOKEN_OFFSET_SECONDS
    assert c["iat"] == c["exp"] - 10

def test_build_claims_reserved_claims_cannot_be_overridden():
    c = tokens.build_claims(spec(claims={"iss": "x", "jti": "x", "sub": "x", "aud": "x", "ok": 1}),
                            make_settings(), NOW)
    assert c["iss"] == "jwks-server" and c["sub"] == "test-user" and c["jti"] != "x"
    assert "aud" not in c and c["ok"] == 1

def test_build_claims_unserializable():
    with pytest.raises(TokenRequestError):
        tokens.build_claims(spec(claims={"x": {1, 2}}), make_settings(), NOW)

def test_build_claims_size_boundary():
    overhead = len('{"x": ""}')
    ok = spec(claims={"x": "a" * (8192 - overhead)})
    tokens.build_claims(ok, make_settings(), NOW)
    with pytest.raises(TokenRequestError):
        tokens.build_claims(spec(claims={"x": "a" * (8192 - overhead + 1)}), make_settings(), NOW)

def test_jti_unique():
    a = tokens.build_claims(spec(), make_settings(), NOW)["jti"]
    b = tokens.build_claims(spec(), make_settings(), NOW)["jti"]
    assert a != b

def _rec():
    return KeyRecord(kid="k", alg="RS256", private_pem=_PAIR[0], public_pem=_PAIR[1],
                     created_at=NOW, not_before=NOW, expires_at=datetime(2999, 1, 1, tzinfo=timezone.utc))

def test_sign_token_signature_valid():
    r = tokens.sign_token(_rec(), spec(), make_settings())
    assert jwt.decode(r.access_token, _PAIR[1], algorithms=["RS256"], issuer="jwks-server")["sub"]

def test_sign_token_wraps_signing_error(monkeypatch):
    def boom(*a, **k): raise jwt.PyJWTError("x")
    monkeypatch.setattr(tokens.jwt, "encode", boom)
    with pytest.raises(TokenRequestError):
        tokens.sign_token(_rec(), spec(), make_settings())

def test_sign_token_decodes_bytes(monkeypatch):
    monkeypatch.setattr(tokens.jwt, "encode", lambda *a, **k: b"abc.def.ghi")
    assert tokens.sign_token(_rec(), spec(), make_settings()).access_token == "abc.def.ghi"

# ---- model helpers ------------------------------------------------------------------
@pytest.mark.parametrize("v,exp", [(True, True), (False, False), (1, True), (0, False),
                                   ("TRUE", True), (" 0 ", False), ("false", False), ("1", True)])
def test_parse_bool_ok(v, exp):
    assert _parse_bool(v) is exp

@pytest.mark.parametrize("v", [2, "yes", None, 1.5])
def test_parse_bool_bad(v):
    with pytest.raises(ValueError):
        _parse_bool(v)

def test_parse_datetime_variants():
    assert _parse_datetime("2026-01-01T00:00:00Z") == NOW
    assert _parse_datetime(NOW) == NOW
    with pytest.raises(ValueError):
        _parse_datetime(12345)
    with pytest.raises(ValueError):
        _parse_datetime("not a date")

def test_subject_precedence():
    assert spec(username="u").subject() == "u"
    assert spec(sub="s", username="s").subject() == "s"
    assert spec().subject() == "test-user"

def test_claims_none_becomes_empty():
    assert spec(claims=None).claims == {}

def test_text_fields_are_stripped():
    assert spec(sub="  bob ").sub == "bob"

# ---- rate limiter -------------------------------------------------------------------
class Clock:
    def __init__(self): self.t = 100.0
    def __call__(self): return self.t

def test_limiter_blocks_then_recovers():
    c = Clock(); l = SlidingWindowLimiter(2, clock=c)
    assert l.allow("a") == (True, 1, 0.0)
    assert l.allow("a")[0] is True
    ok, rem, wait = l.allow("a")
    assert ok is False and rem == 0 and 0 < wait <= 1
    c.t += 1.01
    assert l.allow("a")[0] is True

def test_limiter_is_per_key():
    l = SlidingWindowLimiter(1, clock=Clock())
    assert l.allow("a")[0] and l.allow("b")[0] and not l.allow("a")[0]

def test_limiter_zero_disabled():
    l = SlidingWindowLimiter(0)
    assert all(l.allow("a")[0] for _ in range(100))

def test_limiter_drops_stale_keys():
    c = Clock(); l = SlidingWindowLimiter(1, clock=c)
    l.allow("old"); c.t += 5; l.allow("new")
    assert "old" not in l._hits

def test_http_rate_limit_429(client_factory):
    c = client_factory(rate_limit_per_second=3)
    codes = [c.get("/health") for _ in range(5)]
    assert [r.status_code for r in codes[:3]] == [200] * 3
    assert codes[3].status_code == 429
    assert codes[3].headers["retry-after"] == "1"
    assert codes[3].headers["x-ratelimit-remaining"] == "0"
    assert codes[0].headers["x-ratelimit-limit"] == "3"

def test_middleware_passes_non_http_scope():
    seen = []
    async def app(scope, receive, send): seen.append(scope["type"])
    mw = RateLimitMiddleware(app, SlidingWindowLimiter(1))
    asyncio.run(mw({"type": "lifespan"}, None, None))
    assert seen == ["lifespan"]

def test_middleware_unknown_client():
    sent = []
    async def app(scope, receive, send): await send({"type": "http.response.start", "status": 200})
    async def send(m): sent.append(m)
    mw = RateLimitMiddleware(app, SlidingWindowLimiter(5))
    asyncio.run(mw({"type": "http"}, None, send))   # no "client" key
    assert sent[0]["status"] == 200 and (b"x-ratelimit-limit", b"5") in sent[0]["headers"]

# ---- main.py -----------------------------------------------------------------------
def test_lifespan_starts_and_stops_rotation_task(client_factory):
    c = client_factory(auto_rotate=True)
    assert c.get("/health").status_code == 200

def test_log_startup_warnings(caplog):
    with caplog.at_level(logging.WARNING):
        _log_startup(make_settings(auto_rotate=True, rotation_interval_seconds=4000,
                                   key_lifetime_seconds=3600))
    text = caplog.text
    assert "JWKS_ADMIN_API_KEY is empty" in text and "Rotation interval" in text

def test_log_startup_quiet_when_configured(caplog):
    with caplog.at_level(logging.WARNING):
        _log_startup(make_settings(admin_api_key="k", auto_rotate=True,
                                   rotation_interval_seconds=60, key_lifetime_seconds=3600))
    assert caplog.text == ""

def test_rotation_loop_rotates_and_survives_errors(caplog):
    calls = []
    class M:
        def rotate_if_due(self):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")
    async def go():
        stop = asyncio.Event()
        t = asyncio.create_task(_rotation_loop(M(), 0.01, stop))
        await asyncio.sleep(0.15); stop.set(); await t
    with caplog.at_level(logging.ERROR):
        asyncio.run(go())
    assert len(calls) >= 2 and "Automatic key rotation failed" in caplog.text

def test_rotation_loop_exits_immediately_when_stopped():
    async def go():
        stop = asyncio.Event(); stop.set()
        await asyncio.wait_for(_rotation_loop(object(), 100, stop), 1)
    asyncio.run(go())

def test_cors_allows_configured_origin(client_factory):
    c = client_factory(cors_origins="https://a.example")
    r = c.options("/auth", headers={"Origin": "https://a.example",
                                    "Access-Control-Request-Method": "POST"})
    assert r.headers["access-control-allow-origin"] == "https://a.example"

def test_cors_blocks_other_origin(client_factory):
    c = client_factory(cors_origins="https://a.example")
    r = c.options("/auth", headers={"Origin": "https://evil.example",
                                    "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in r.headers

def test_cors_rejects_unlisted_method(client):
    r = client.options("/keys", headers={"Origin": "https://x", "Access-Control-Request-Method": "DELETE"})
    assert r.status_code == 400

def test_entrypoint_main_runs_uvicorn(monkeypatch):
    captured = {}
    monkeypatch.setattr(entry.uvicorn, "run", lambda app, **kw: captured.update(kw))
    monkeypatch.setattr(entry, "Settings", lambda: make_settings(host="127.0.0.1", port=9999))
    entry.main()
    assert captured["port"] == 9999 and captured["host"] == "127.0.0.1"
