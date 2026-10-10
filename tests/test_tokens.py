"""Key status, claim building, and signing-mode selection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models import IssueTokenRequest, KeyRecord, KeySelectionError, KeyStatus, SignKeyMode, TokenRequestError
from app.tokens import build_claims, resolve_sign_mode
from tests.helpers import make_settings


def _record(not_before: datetime, expires_at: datetime, *, revoked: bool = False) -> KeyRecord:
    return KeyRecord(
        kid="key-test",
        alg="RS256",
        private_pem="unused",
        public_pem="unused",
        created_at=not_before,
        not_before=not_before,
        expires_at=expires_at,
        revoked=revoked,
    )


def test_status_follows_the_validity_window() -> None:
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    record = _record(now + timedelta(hours=1), now + timedelta(days=1))
    assert record.status_at(now) is KeyStatus.PENDING
    assert record.status_at(now + timedelta(hours=2)) is KeyStatus.ACTIVE
    assert record.status_at(record.not_before) is KeyStatus.ACTIVE
    assert record.status_at(record.expires_at) is KeyStatus.EXPIRED
    record.revoked = True
    assert record.status_at(now + timedelta(hours=2)) is KeyStatus.REVOKED


def test_repr_hides_key_material() -> None:
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    record = _record(now, now + timedelta(hours=1))
    record.private_pem = "-----BEGIN PRIVATE KEY-----\nSECRET"
    assert "SECRET" not in repr(record)


def test_resolve_sign_mode() -> None:
    assert resolve_sign_mode(IssueTokenRequest()) == (None, SignKeyMode.ACTIVE)
    assert resolve_sign_mode(IssueTokenRequest(use_inactive=True)) == (None, SignKeyMode.INACTIVE)
    assert resolve_sign_mode(IssueTokenRequest(key_state="pending")) == (None, SignKeyMode.INACTIVE)
    assert resolve_sign_mode(IssueTokenRequest(use_expired_key=True)) == (None, SignKeyMode.EXPIRED)
    assert resolve_sign_mode(IssueTokenRequest(kid="key-1")) == ("key-1", SignKeyMode.ACTIVE)
    with pytest.raises(KeySelectionError):
        resolve_sign_mode(IssueTokenRequest(use_inactive=True, use_expired_key=True))
    with pytest.raises(KeySelectionError):
        resolve_sign_mode(IssueTokenRequest(kid="key-1", key_state="expired"))
    with pytest.raises(KeySelectionError):
        resolve_sign_mode(IssueTokenRequest(key_state="active", use_inactive=True))


def test_expired_flag_moves_exp_into_the_past_without_replacing_registered_claims() -> None:
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    spec = IssueTokenRequest(
        expired=True,
        sub="alice",
        ttl_seconds=30,
        claims={"exp": 9_999_999_999, "iss": "evil", "role": "admin"},
    )
    claims = build_claims(spec, make_settings(), now)
    assert claims["sub"] == "alice"
    assert claims["iss"] == "jwks-server"
    assert claims["role"] == "admin"
    assert claims["exp"] == int((now - timedelta(seconds=120)).timestamp())
    assert int(claims["exp"]) < int(now.timestamp())


def test_claims_must_be_json_serializable() -> None:
    spec = IssueTokenRequest(claims={"when": datetime.now(timezone.utc)})
    with pytest.raises(TokenRequestError):
        build_claims(spec, make_settings(), datetime.now(timezone.utc))
