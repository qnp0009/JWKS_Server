"""Persistence backends."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.crypto import generate_rsa_keypair
from app.models import KeyRecord
from app.stores import FileKeyStore, MemoryKeyStore, SqliteKeyStore, StoreError


@pytest.fixture(scope="module")
def pem_pair() -> tuple[str, str]:
    return generate_rsa_keypair(2048)


def _record(pem_pair: tuple[str, str], kid: str = "kid-1") -> KeyRecord:
    private_pem, public_pem = pem_pair
    now = datetime.now(timezone.utc)
    return KeyRecord(
        kid=kid,
        alg="RS256",
        private_pem=private_pem,
        public_pem=public_pem,
        created_at=now,
        not_before=now,
        expires_at=now + timedelta(hours=1),
    )


def test_memory_store_is_process_local(pem_pair: tuple[str, str]) -> None:
    store = MemoryKeyStore()
    store.upsert(_record(pem_pair))
    assert store.get("kid-1") is not None
    assert MemoryKeyStore().get("kid-1") is None


@pytest.mark.parametrize("backend", ["file", "sqlite"])
def test_durable_store_reopens(tmp_path, pem_pair: tuple[str, str], backend: str) -> None:
    path = tmp_path / ("keystore.json" if backend == "file" else "keys.db")
    store = FileKeyStore(path) if backend == "file" else SqliteKeyStore(path)
    store.upsert(_record(pem_pair))
    store.upsert(_record(pem_pair, "kid-2"))
    reopened = FileKeyStore(path) if backend == "file" else SqliteKeyStore(path)
    loaded = reopened.get("kid-1")
    assert loaded is not None
    assert loaded.private_pem == pem_pair[0]
    assert loaded.public_pem == pem_pair[1]
    assert {record.kid for record in reopened.list_keys()} == {"kid-1", "kid-2"}


def test_file_store_rejects_corrupt_documents(tmp_path, pem_pair: tuple[str, str]) -> None:
    invalid = tmp_path / "bad.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(StoreError):
        FileKeyStore(invalid)

    wrong_version = tmp_path / "version.json"
    wrong_version.write_text('{"version": 2, "keys": []}', encoding="utf-8")
    with pytest.raises(StoreError):
        FileKeyStore(wrong_version)

    other_public = generate_rsa_keypair(2048)[1]
    mismatched = _record(pem_pair)
    mismatched.public_pem = other_public
    with pytest.raises(StoreError):
        FileKeyStore(tmp_path / "mismatch.json").upsert(mismatched)
