"""Storage backends and crypto helpers."""
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.config import Settings
from app.crypto import _b64url_uint, generate_rsa_keypair, public_jwk, validate_keypair
from app.models import KeyRecord
from app.stores import (FileKeyStore, MemoryKeyStore, SqliteKeyStore, StoreError, build_store)
from tests_llm.conftest import _PAIR

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)

def rec(kid="a", **kw):
    base = dict(kid=kid, alg="RS256", private_pem=_PAIR[0], public_pem=_PAIR[1],
                created_at=T0, not_before=T0, expires_at=T0 + timedelta(days=1))
    base.update(kw)
    return KeyRecord(**base)

@pytest.fixture(params=["memory", "file", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return MemoryKeyStore()
    if request.param == "file":
        return FileKeyStore(tmp_path / "ks.json")
    return SqliteKeyStore(tmp_path / "k.db")

# ---- shared CRUD contract ---------------------------------------------------
def test_empty_store(store):
    assert store.list_keys() == [] and store.get("x") is None

def test_upsert_get_list(store):
    store.upsert(rec("a")); store.upsert(rec("b"))
    assert store.get("a").kid == "a" and {r.kid for r in store.list_keys()} == {"a", "b"}

def test_upsert_updates_existing(store):
    store.upsert(rec("a")); store.upsert(rec("a", revoked=True))
    assert store.get("a").revoked is True and len(store.list_keys()) == 1

def test_upsert_rejects_mismatched_pair(store):
    other_pub = generate_rsa_keypair(2048)[1]
    with pytest.raises(StoreError):
        store.upsert(rec("bad", public_pem=other_pub))

def test_upsert_rejects_garbage_pem(store):
    with pytest.raises(StoreError):
        store.upsert(rec("bad", private_pem="junk"))

# ---- file store --------------------------------------------------------------
def test_file_store_persists_across_instances(tmp_path):
    p = tmp_path / "d" / "ks.json"
    FileKeyStore(p).upsert(rec("a"))
    assert FileKeyStore(p).get("a") is not None

def test_file_store_has_no_tmp_leftover(tmp_path):
    p = tmp_path / "ks.json"; FileKeyStore(p).upsert(rec("a"))
    assert not list(tmp_path.glob("*.tmp"))

@pytest.mark.skipif(os.name != "posix", reason="chmod semantics are POSIX only")
def test_file_store_permissions_0600(tmp_path):
    p = tmp_path / "ks.json"; FileKeyStore(p).upsert(rec("a"))
    assert (p.stat().st_mode & 0o777) == 0o600

def test_file_store_keeps_private_key_in_plaintext(tmp_path):
    """Documents a data-protection weakness: private key is not encrypted at rest."""
    p = tmp_path / "ks.json"; FileKeyStore(p).upsert(rec("a"))
    assert "BEGIN PRIVATE KEY" in p.read_text()

@pytest.mark.parametrize("content", [
    "not json",
    json.dumps([]),
    json.dumps({"version": 2, "keys": []}),
    json.dumps({"version": 1}),
    json.dumps({"version": 1, "keys": ["str"]}),
    json.dumps({"version": 1, "keys": [{"kid": "x"}]}),
])
def test_file_store_rejects_corrupt_files(tmp_path, content):
    p = tmp_path / "ks.json"; p.write_text(content)
    with pytest.raises(StoreError):
        FileKeyStore(p)

def test_file_store_rejects_duplicate_kid(tmp_path):
    p = tmp_path / "ks.json"
    d = rec("a").to_dict()
    p.write_text(json.dumps({"version": 1, "keys": [d, d]}))
    with pytest.raises(StoreError, match="Duplicate"):
        FileKeyStore(p)

# ---- sqlite store ------------------------------------------------------------
def test_sqlite_persists(tmp_path):
    p = tmp_path / "k.db"; SqliteKeyStore(p).upsert(rec("a"))
    assert SqliteKeyStore(p).get("a").kid == "a"

def test_sqlite_get_is_parameterised(tmp_path):
    s = SqliteKeyStore(tmp_path / "k.db"); s.upsert(rec("a"))
    assert s.get("a' OR '1'='1") is None
    assert s.get("a'; DROP TABLE keys;--") is None
    assert s.get("a") is not None

def test_sqlite_invalid_row_raises_store_error(tmp_path):
    p = tmp_path / "k.db"; s = SqliteKeyStore(p)
    with sqlite3.connect(p) as c:
        c.execute("INSERT INTO keys VALUES ('x','RS256','junk','junk',?,?,?,0)",
                  (T0.isoformat(),) * 3)
    with pytest.raises(StoreError):
        s.get("x")
    with pytest.raises(StoreError):
        s.list_keys()

def test_sqlite_session_rolls_back_on_error(tmp_path):
    s = SqliteKeyStore(tmp_path / "k.db")
    with pytest.raises(RuntimeError):
        with s._session() as c:
            c.execute("INSERT INTO keys VALUES ('z','a','b','c','d','e','f',0)")
            raise RuntimeError
    with sqlite3.connect(tmp_path / "k.db") as c:
        assert c.execute("SELECT count(*) FROM keys").fetchone()[0] == 0

# ---- build_store / settings -------------------------------------------------
def test_build_store_variants(tmp_path):
    assert isinstance(build_store(Settings(_env_file=None, storage_backend="memory")), MemoryKeyStore)
    assert isinstance(build_store(Settings(_env_file=None, storage_backend="file",
                      storage_path=str(tmp_path / "a.json"))), FileKeyStore)
    assert isinstance(build_store(Settings(_env_file=None, storage_backend="sqlite",
                      storage_path=str(tmp_path / "a.db"))), SqliteKeyStore)

def test_build_store_unsupported_backend():
    fake = SimpleNamespace(storage_backend="redis", resolved_storage_path=lambda: Path("x"))
    with pytest.raises(StoreError):
        build_store(fake)

def test_resolved_storage_path_defaults():
    assert Settings(_env_file=None, storage_backend="sqlite").resolved_storage_path() == Path("data/keys.db")
    assert Settings(_env_file=None, storage_backend="file").resolved_storage_path() == Path("data/keystore.json")
    assert Settings(_env_file=None, storage_path="z.db").resolved_storage_path() == Path("z.db")

@pytest.mark.parametrize("kw", [{"rsa_key_size": 1024}, {"rsa_key_size": 8192},
                                {"key_lifetime_seconds": 59}, {"rotation_interval_seconds": 29},
                                {"port": 0}, {"port": 70000}, {"rate_limit_per_second": -1},
                                {"storage_backend": "mongo"}, {"issuer": ""}])
def test_settings_validation_rejects(kw):
    with pytest.raises(Exception):
        Settings(_env_file=None, **kw)

def test_settings_env_prefix(monkeypatch):
    monkeypatch.setenv("JWKS_ISSUER", "me")
    assert Settings(_env_file=None).issuer == "me"

# ---- crypto ------------------------------------------------------------------
def test_generate_pair_formats():
    priv, pub = generate_rsa_keypair(2048)
    assert priv.startswith("-----BEGIN PRIVATE KEY-----") and pub.startswith("-----BEGIN PUBLIC KEY-----")
    validate_keypair(priv, pub)

def test_validate_rejects_invalid_pem():
    with pytest.raises(ValueError, match="valid PEM"):
        validate_keypair("x", "y")

def test_validate_rejects_mismatch():
    with pytest.raises(ValueError, match="match"):
        validate_keypair(_PAIR[0], generate_rsa_keypair(2048)[1])

def _ec_pair():
    k = ec.generate_private_key(ec.SECP256R1())
    return (k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode(),
            k.public_key().public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo).decode())

def test_validate_rejects_non_rsa():
    with pytest.raises(ValueError, match="RSA"):
        validate_keypair(*_ec_pair())

def test_public_jwk_rejects_non_rsa():
    with pytest.raises(ValueError):
        public_jwk(_ec_pair()[1], kid="k", alg="RS256")

def test_public_jwk_fields():
    j = public_jwk(_PAIR[1], kid="k", alg="RS256")
    assert j["e"] == "AQAB" and j["kid"] == "k" and "=" not in j["n"]

def test_b64url_uint_edge_cases():
    assert _b64url_uint(0) == "AA"
    assert _b64url_uint(255) == "_w"
    assert _b64url_uint(256) == "AQA"
