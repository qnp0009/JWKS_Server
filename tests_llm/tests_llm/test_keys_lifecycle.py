"""White-box tests: KeyRecord status rules and KeyManager branches."""
from datetime import datetime, timedelta, timezone

import pytest

import app.keys as keys_module
from app.keys import KeyManager
from app.models import (KeyNotFoundError, KeyRecord, KeySelectionError, KeyStatus,
                        NoActiveKeyError, SignKeyMode)
from app.stores import MemoryKeyStore
from tests_llm.conftest import _PAIR, make_settings

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def record(**kw):
    base = dict(kid="k", alg="RS256", private_pem=_PAIR[0], public_pem=_PAIR[1],
                created_at=T0, not_before=T0, expires_at=T0 + timedelta(hours=1))
    base.update(kw)
    return KeyRecord(**base)


# ---- KeyRecord.status_at: boundary values --------------------------------
def test_status_pending_just_before_not_before():
    assert record().status_at(T0 - timedelta(microseconds=1)) is KeyStatus.PENDING

def test_status_active_exactly_at_not_before():
    assert record().status_at(T0) is KeyStatus.ACTIVE

def test_status_active_just_before_expiry():
    assert record().status_at(T0 + timedelta(hours=1) - timedelta(microseconds=1)) is KeyStatus.ACTIVE

def test_status_expired_exactly_at_expiry():
    assert record().status_at(T0 + timedelta(hours=1)) is KeyStatus.EXPIRED

def test_status_revoked_wins_over_window():
    assert record(revoked=True).status_at(T0 + timedelta(minutes=1)) is KeyStatus.REVOKED

def test_naive_datetimes_are_treated_as_utc():
    r = record(not_before=datetime(2026, 1, 1), expires_at=datetime(2026, 1, 2))
    assert r.not_before.tzinfo is not None
    assert r.status_at(datetime(2026, 1, 1, 12)) is KeyStatus.ACTIVE

def test_non_utc_offset_is_normalised():
    tz = timezone(timedelta(hours=7))
    r = record(not_before=datetime(2026, 1, 1, 7, tzinfo=tz))
    assert r.not_before == T0

def test_record_roundtrip_and_repr_hides_private_key():
    r = record()
    assert KeyRecord.from_dict(r.to_dict()) == r
    assert "BEGIN PRIVATE KEY" not in repr(r)


# ---- KeyManager.bootstrap / create ---------------------------------------
def test_bootstrap_creates_exactly_one_active_key(manager):
    assert manager.active_count() == 1

def test_bootstrap_is_idempotent(manager):
    manager.bootstrap()
    assert manager.active_count() == 1

def test_create_key_default_window_uses_key_lifetime(manager, settings):
    r = manager.create_key()
    assert (r.expires_at - r.not_before).total_seconds() == settings.key_lifetime_seconds

def test_create_key_only_not_before_adds_lifetime(manager):
    nb = datetime.now(timezone.utc) + timedelta(hours=2)
    r = manager.create_key(not_before=nb, lifetime_seconds=600)
    assert r.expires_at - r.not_before == timedelta(seconds=600)

def test_create_key_only_expires_at_subtracts_lifetime(manager):
    end = datetime.now(timezone.utc) + timedelta(hours=2)
    r = manager.create_key(expires_at=end, lifetime_seconds=600)
    assert end - r.not_before == timedelta(seconds=600)

def test_create_key_rejects_non_positive_lifetime(manager):
    with pytest.raises(KeySelectionError):
        manager.create_key(lifetime_seconds=0)

def test_create_key_rejects_end_not_after_start(manager):
    t = datetime.now(timezone.utc)
    with pytest.raises(KeySelectionError):
        manager.create_key(not_before=t, expires_at=t)

def test_kid_collision_loop_retries(manager, monkeypatch):
    first = manager.create_key().kid
    seq = iter([first.removeprefix("key-"), "f" * 32])
    class U:  # fake uuid
        def __init__(self, h): self.hex = h
    monkeypatch.setattr(keys_module.uuid, "uuid4", lambda: U(next(seq)))
    assert manager.create_key().kid == "key-" + "f" * 32


# ---- rotation -------------------------------------------------------------
def test_rotate_adds_key_and_keeps_old_one_published(manager):
    old = manager.jwks()["keys"][0]["kid"]
    manager.rotate()
    kids = {k["kid"] for k in manager.jwks()["keys"]}
    assert old in kids and len(kids) == 2

def test_rotate_if_due_not_due_returns_none(manager):
    assert manager.rotate_if_due() is None

def test_rotate_if_due_creates_when_old_enough(monkeypatch):
    s = make_settings(rotation_interval_seconds=30, key_lifetime_seconds=3600)
    m = KeyManager(MemoryKeyStore(), s); m.bootstrap()
    later = datetime.now(timezone.utc) + timedelta(seconds=31)
    monkeypatch.setattr(keys_module, "_utcnow", lambda: later)
    assert m.rotate_if_due() is not None
    assert m.active_count() == 2

def test_rotate_if_due_with_no_active_key_creates_one(manager):
    for k in manager.list_metadata():
        manager.revoke(k.kid)
    assert manager.rotate_if_due() is not None

def test_bootstrap_with_auto_rotate_no_extra_key_when_fresh():
    m = KeyManager(MemoryKeyStore(), make_settings(auto_rotate=True)); m.bootstrap()
    assert m.active_count() == 1


# ---- revoke / metadata ----------------------------------------------------
def test_revoke_removes_key_from_jwks(manager):
    kid = manager.jwks()["keys"][0]["kid"]
    manager.revoke(kid)
    assert manager.jwks() == {"keys": []}
    assert manager.get_metadata(kid).status is KeyStatus.REVOKED

def test_revoke_unknown_raises(manager):
    with pytest.raises(KeyNotFoundError):
        manager.revoke("nope")

def test_get_metadata_unknown_raises(manager):
    with pytest.raises(KeyNotFoundError):
        manager.get_metadata("nope")

def test_list_metadata_newest_first(manager):
    manager.rotate()
    items = manager.list_metadata()
    assert items[0].created_at >= items[1].created_at

def test_metadata_jwk_has_no_private_members(manager):
    jwk = manager.list_metadata()[0].jwk
    assert not ({"d", "p", "q", "dp", "dq", "qi"} & set(jwk))


# ---- select_signing_key ---------------------------------------------------
def test_select_default_returns_active(manager):
    assert manager.select_signing_key(kid=None, mode=SignKeyMode.ACTIVE).kid

def test_select_without_active_raises(manager):
    for k in manager.list_metadata():
        manager.revoke(k.kid)
    with pytest.raises(NoActiveKeyError):
        manager.select_signing_key(kid=None, mode=SignKeyMode.ACTIVE)

def test_select_explicit_kid_unknown(manager):
    with pytest.raises(KeyNotFoundError):
        manager.select_signing_key(kid="zzz", mode=SignKeyMode.ACTIVE)

def test_select_explicit_revoked_refused(manager):
    kid = manager.jwks()["keys"][0]["kid"]; manager.revoke(kid)
    with pytest.raises(KeySelectionError):
        manager.select_signing_key(kid=kid, mode=SignKeyMode.ACTIVE)

def test_select_inactive_creates_then_reuses_pending(manager):
    a = manager.select_signing_key(kid=None, mode=SignKeyMode.INACTIVE)
    b = manager.select_signing_key(kid=None, mode=SignKeyMode.INACTIVE)
    assert a.kid == b.kid
    assert a.status_at(datetime.now(timezone.utc)) is KeyStatus.PENDING

def test_select_expired_creates_then_reuses(manager):
    a = manager.select_signing_key(kid=None, mode=SignKeyMode.EXPIRED)
    b = manager.select_signing_key(kid=None, mode=SignKeyMode.EXPIRED)
    assert a.kid == b.kid
    assert a.status_at(datetime.now(timezone.utc)) is KeyStatus.EXPIRED

def test_pending_and_expired_keys_never_published(manager):
    manager.select_signing_key(kid=None, mode=SignKeyMode.INACTIVE)
    manager.select_signing_key(kid=None, mode=SignKeyMode.EXPIRED)
    assert len(manager.jwks()["keys"]) == 1
