"""Environment-backed settings for the JWKS server."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

StorageBackend = Literal["memory", "file", "sqlite"]


class Settings(BaseSettings):
    """Runtime configuration.

    Values come from the process environment and an optional ``.env`` file.
    Names are prefixed with ``JWKS_``, for example ``JWKS_STORAGE_BACKEND``.
    """

    model_config = SettingsConfigDict(
        env_prefix="JWKS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    issuer: str = Field(default="jwks-server", min_length=1)
    rsa_key_size: int = Field(default=2048, ge=2048, le=4096)
    algorithm: Literal["RS256"] = "RS256"
    key_lifetime_seconds: int = Field(default=24 * 60 * 60, ge=60)
    rotation_interval_seconds: int = Field(default=12 * 60 * 60, ge=30)
    auto_rotate: bool = True
    token_ttl_seconds: int = Field(default=60 * 60, ge=1, le=30 * 24 * 60 * 60)
    storage_backend: StorageBackend = "memory"
    storage_path: str | None = None
    admin_api_key: str = ""
    cors_origins: str = "*"
    # Requests allowed per client address in a rolling one-second window. Zero disables the limit.
    rate_limit_per_second: int = Field(default=10, ge=0)
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)

    def resolved_storage_path(self) -> Path:
        """Return the on-disk location for the file or sqlite backend."""
        if self.storage_path:
            return Path(self.storage_path)
        if self.storage_backend == "sqlite":
            return Path("data") / "keys.db"
        return Path("data") / "keystore.json"
