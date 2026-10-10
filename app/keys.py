"""Signing-key lifecycle: create, rotate, revoke, and select."""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone

from app.config import Settings
from app.crypto import generate_rsa_keypair, public_jwk
from app.models import (
    KeyMetadata,
    KeyNotFoundError,
    KeyRecord,
    KeySelectionError,
    KeyStatus,
    NoActiveKeyError,
    SignKeyMode,
    ensure_utc,
)
from app.stores import FileKeyStore, MemoryKeyStore, SqliteKeyStore

logger = logging.getLogger(__name__)

# A test key requested before any pending key exists waits at least this long
# before it would become active, so it stays out of the JWKS document.
_MIN_PENDING_DELAY_SECONDS = 60 * 60

KeyStore = MemoryKeyStore | FileKeyStore | SqliteKeyStore


class KeyManager:
    """Owns the validity rules on top of a key store.

    A key is published in JWKS only while it is active: not revoked, not
    before ``not_before``, and strictly before ``expires_at``. Rotation
    adds a new active key and leaves the previous one published until its
    own expiry, which gives resource servers time to accept both.
    """

    def __init__(self, store: KeyStore, settings: Settings) -> None:
        self.store = store
        self._settings = settings
        self._lock = threading.RLock()

    def bootstrap(self) -> None:
        """Guarantee one active key, then rotate immediately when the schedule is already due."""
        with self._lock:
            if not self._by_status(KeyStatus.ACTIVE):
                self._create_unlocked()
            if self._settings.auto_rotate:
                self._rotate_if_due_unlocked()

    def create_key(
        self,
        *,
        not_before: datetime | None = None,
        expires_at: datetime | None = None,
        lifetime_seconds: int | None = None,
    ) -> KeyRecord:
        with self._lock:
            return self._create_unlocked(
                not_before=not_before,
                expires_at=expires_at,
                lifetime_seconds=lifetime_seconds,
            )

    def rotate(self) -> KeyRecord:
        """Publish a new active key now. Older active keys remain until they expire."""
        return self.create_key()

    def rotate_if_due(self) -> KeyRecord | None:
        with self._lock:
            return self._rotate_if_due_unlocked()

    def revoke(self, kid: str) -> KeyRecord:
        with self._lock:
            record = self.store.get(kid)
            if record is None:
                raise KeyNotFoundError(kid)
            record.revoked = True
            self.store.upsert(record)
            logger.info("Revoked signing key kid=%s", kid)
            return record

    def list_metadata(self) -> list[KeyMetadata]:
        with self._lock:
            records = list(self.store.list_keys())
            records.sort(key=lambda record: record.created_at, reverse=True)
            return [self._metadata(record) for record in records]

    def get_metadata(self, kid: str) -> KeyMetadata:
        with self._lock:
            record = self.store.get(kid)
            if record is None:
                raise KeyNotFoundError(kid)
            return self._metadata(record)

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        """Return the JWKS document. Only active public keys are included."""
        with self._lock:
            keys = [
                public_jwk(record.public_pem, kid=record.kid, alg=record.alg)
                for record in self._by_status(KeyStatus.ACTIVE)
            ]
            return {"keys": keys}

    def active_count(self) -> int:
        with self._lock:
            return len(self._by_status(KeyStatus.ACTIVE))

    def select_signing_key(self, *, kid: str | None, mode: SignKeyMode) -> KeyRecord:
        """Choose the private key for a token.

        An explicit ``kid`` may be pending or expired so callers can test
        those cases. A revoked key is refused. Inactive and expired modes
        reuse an existing key of that status, or create one.
        """
        with self._lock:
            if kid:
                record = self.store.get(kid)
                if record is None:
                    raise KeyNotFoundError(kid)
                if record.revoked:
                    raise KeySelectionError(f"Key '{kid}' is revoked")
                return record
            if mode is SignKeyMode.INACTIVE:
                return self._pending_or_create()
            if mode is SignKeyMode.EXPIRED:
                return self._expired_or_create()
            active = self._by_status(KeyStatus.ACTIVE)
            if not active:
                raise NoActiveKeyError(
                    "No active signing key is available. Create or rotate a key and try again."
                )
            return active[0]

    def _rotate_if_due_unlocked(self) -> KeyRecord | None:
        active = self._by_status(KeyStatus.ACTIVE)
        if not active:
            return self._create_unlocked()
        newest = active[0]
        age = _utcnow() - newest.created_at
        if age >= timedelta(seconds=self._settings.rotation_interval_seconds):
            return self._create_unlocked()
        return None

    def _pending_or_create(self) -> KeyRecord:
        pending = self._by_status(KeyStatus.PENDING)
        if pending:
            return pending[0]
        delay = max(self._settings.key_lifetime_seconds, _MIN_PENDING_DELAY_SECONDS)
        not_before = _utcnow() + timedelta(seconds=delay)
        return self._create_unlocked(not_before=not_before)

    def _expired_or_create(self) -> KeyRecord:
        expired = self._by_status(KeyStatus.EXPIRED)
        if expired:
            return expired[0]
        expires_at = _utcnow() - timedelta(seconds=60)
        not_before = expires_at - timedelta(seconds=self._settings.key_lifetime_seconds)
        return self._create_unlocked(not_before=not_before, expires_at=expires_at)

    def _create_unlocked(
        self,
        *,
        not_before: datetime | None = None,
        expires_at: datetime | None = None,
        lifetime_seconds: int | None = None,
    ) -> KeyRecord:
        lifetime = lifetime_seconds if lifetime_seconds is not None else self._settings.key_lifetime_seconds
        if lifetime <= 0:
            raise KeySelectionError("lifetime_seconds must be positive")
        start = ensure_utc(not_before) if not_before is not None else None
        end = ensure_utc(expires_at) if expires_at is not None else None
        now = _utcnow()
        if start is None and end is None:
            start = now
            end = now + timedelta(seconds=lifetime)
        elif start is not None and end is None:
            end = start + timedelta(seconds=lifetime)
        elif start is None and end is not None:
            start = end - timedelta(seconds=lifetime)
        if start is None or end is None or end <= start:
            raise KeySelectionError("expires_at must be later than not_before")

        private_pem, public_pem = generate_rsa_keypair(self._settings.rsa_key_size)
        kid = f"key-{uuid.uuid4().hex}"
        while self.store.get(kid) is not None:
            kid = f"key-{uuid.uuid4().hex}"
        record = KeyRecord(
            kid=kid,
            alg=self._settings.algorithm,
            private_pem=private_pem,
            public_pem=public_pem,
            created_at=now,
            not_before=start,
            expires_at=end,
        )
        self.store.upsert(record)
        logger.info(
            "Generated signing key kid=%s status=%s not_before=%s expires_at=%s",
            record.kid,
            record.status_at(now).value,
            record.not_before.isoformat(),
            record.expires_at.isoformat(),
        )
        return record

    def _by_status(self, status: KeyStatus) -> list[KeyRecord]:
        now = _utcnow()
        matched = [record for record in self.store.list_keys() if record.status_at(now) == status]
        matched.sort(key=lambda record: record.created_at, reverse=True)
        return matched

    def _metadata(self, record: KeyRecord) -> KeyMetadata:
        return KeyMetadata(
            kid=record.kid,
            alg=record.alg,
            status=record.status_at(_utcnow()),
            created_at=record.created_at,
            not_before=record.not_before,
            expires_at=record.expires_at,
            revoked=record.revoked,
            jwk=public_jwk(record.public_pem, kid=record.kid, alg=record.alg),
        )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)
