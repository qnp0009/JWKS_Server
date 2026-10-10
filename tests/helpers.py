"""Test builders kept outside conftest so test modules can import them."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

ADMIN_KEY = "test-admin"


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "storage_backend": "memory",
        "auto_rotate": False,
        "admin_api_key": ADMIN_KEY,
        "key_lifetime_seconds": 3600,
        "rotation_interval_seconds": 1800,
        "token_ttl_seconds": 900,
        "rsa_key_size": 2048,
        "issuer": "jwks-server",
        "host": "127.0.0.1",
        "port": 8000,
        "rate_limit_per_second": 0,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


def open_client(settings: Settings | None = None) -> TestClient:
    settings = settings or make_settings()
    client = TestClient(create_app(settings))
    client.__enter__()
    if settings.admin_api_key:
        client.headers["X-Admin-Key"] = settings.admin_api_key
    return client
