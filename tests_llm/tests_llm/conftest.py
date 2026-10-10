"""Shared fixtures for the LLM-generated suite (kept apart from tests/)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import app.keys as keys_module
from app.config import Settings
from app.crypto import generate_rsa_keypair
from app.keys import KeyManager
from app.main import create_app
from app.stores import MemoryKeyStore

_PAIR = generate_rsa_keypair(2048)  # generated once: RSA generation is slow


@pytest.fixture(autouse=True)
def fast_keys(monkeypatch):
    """Reuse one RSA pair inside KeyManager so each test stays fast."""
    monkeypatch.setattr(keys_module, "generate_rsa_keypair", lambda size: _PAIR)


def make_settings(**overrides) -> Settings:
    base = dict(
        _env_file=None,
        auto_rotate=False,
        rate_limit_per_second=0,
        admin_api_key="",
        storage_backend="memory",
    )
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def settings():
    return make_settings()


@pytest.fixture
def manager(settings):
    m = KeyManager(MemoryKeyStore(), settings)
    m.bootstrap()
    return m


@pytest.fixture
def client_factory():
    opened = []

    def _make(**overrides) -> TestClient:
        c = TestClient(create_app(make_settings(**overrides)))
        c.__enter__()
        opened.append(c)
        return c

    yield _make
    for c in opened:
        c.__exit__(None, None, None)


@pytest.fixture
def client(client_factory):
    return client_factory()


@pytest.fixture
def secured_client(client_factory):
    return client_factory(admin_api_key="s3cret")
