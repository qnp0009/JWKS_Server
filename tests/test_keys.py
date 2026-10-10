"""Rotation and JWKS membership at the key-manager layer."""

from __future__ import annotations

from datetime import timedelta

from app.keys import KeyManager, _utcnow
from app.models import KeyStatus
from app.stores import MemoryKeyStore
from tests.helpers import make_settings


def test_jwks_publishes_only_the_active_key() -> None:
    manager = KeyManager(MemoryKeyStore(), make_settings())
    active = manager.create_key()
    pending = manager.create_key(not_before=_utcnow() + timedelta(days=1))
    expired_at = _utcnow() - timedelta(minutes=5)
    expired = manager.create_key(
        not_before=expired_at - timedelta(hours=2),
        expires_at=expired_at,
    )

    published = {item["kid"] for item in manager.jwks()["keys"]}
    assert published == {active.kid}
    assert manager.get_metadata(pending.kid).status is KeyStatus.PENDING
    assert manager.get_metadata(expired.kid).status is KeyStatus.EXPIRED
    for item in manager.jwks()["keys"]:
        assert item["e"] == "AQAB"
        assert "=" not in item["n"]
        assert set(item) == {"kty", "use", "alg", "kid", "n", "e"}


def test_rotate_if_due_keeps_the_previous_public_key() -> None:
    settings = make_settings(rotation_interval_seconds=60, key_lifetime_seconds=3600)
    manager = KeyManager(MemoryKeyStore(), settings)
    first = manager.create_key()
    first.created_at = _utcnow() - timedelta(seconds=120)
    created = manager.rotate_if_due()
    assert created is not None
    assert created.kid != first.kid
    published = [item["kid"] for item in manager.jwks()["keys"]]
    assert published[0] == created.kid
    assert first.kid in published
    assert manager.rotate_if_due() is None
