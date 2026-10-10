"""Domain records and HTTP schemas.

Storage records keep private key material. Response models never do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Self

from pydantic import BaseModel, Field, field_validator, model_validator


class KeyStatus(str, Enum):
    """Lifecycle of a signing key as observed at a single instant."""

    PENDING = "pending"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class SignKeyMode(str, Enum):
    """Which key the token endpoint should sign with."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPIRED = "expired"


def ensure_utc(value: datetime) -> datetime:
    """Return an aware UTC datetime. Naive values are interpreted as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        return ensure_utc(value)
    if isinstance(value, str):
        return ensure_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    raise ValueError("Expected an ISO-8601 timestamp")


def _parse_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1"}:
            return True
        if lowered in {"false", "0"}:
            return False
    raise ValueError("Expected a boolean")


@dataclass
class KeyRecord:
    """One RSA signing key and the window during which it may appear in JWKS."""

    kid: str
    alg: str
    private_pem: str = field(repr=False)
    public_pem: str = field(repr=False)
    created_at: datetime
    not_before: datetime
    expires_at: datetime
    revoked: bool = False

    def __post_init__(self) -> None:
        self.created_at = ensure_utc(self.created_at)
        self.not_before = ensure_utc(self.not_before)
        self.expires_at = ensure_utc(self.expires_at)

    def status_at(self, now: datetime) -> KeyStatus:
        """Classify the key. Revocation wins over the validity window."""
        if self.revoked:
            return KeyStatus.REVOKED
        current = ensure_utc(now)
        if current < self.not_before:
            return KeyStatus.PENDING
        if current >= self.expires_at:
            return KeyStatus.EXPIRED
        return KeyStatus.ACTIVE

    def to_dict(self) -> dict[str, object]:
        return {
            "kid": self.kid,
            "alg": self.alg,
            "private_pem": self.private_pem,
            "public_pem": self.public_pem,
            "created_at": self.created_at.isoformat(),
            "not_before": self.not_before.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "revoked": self.revoked,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KeyRecord:
        return cls(
            kid=str(data["kid"]),
            alg=str(data["alg"]),
            private_pem=str(data["private_pem"]),
            public_pem=str(data["public_pem"]),
            created_at=_parse_datetime(data["created_at"]),
            not_before=_parse_datetime(data["not_before"]),
            expires_at=_parse_datetime(data["expires_at"]),
            revoked=_parse_bool(data.get("revoked", False)),
        )


class IssueTokenRequest(BaseModel):
    """Input for POST /auth and POST /sign.

    Query parameters and a JSON body accept the same fields. When both are
    present, the body wins. ``expired`` controls the token lifetime.
    ``key_state``, ``use_inactive``, and ``use_expired_key`` choose the
    signing key and are independent of ``expired``.
    """

    sub: str | None = Field(default=None, max_length=256)
    username: str | None = Field(default=None, max_length=256)
    aud: str | None = Field(default=None, max_length=256)
    expired: bool = False
    kid: str | None = Field(default=None, max_length=128)
    key_state: Literal["active", "inactive", "pending", "expired"] | None = None
    use_inactive: bool = False
    use_expired_key: bool = False
    ttl_seconds: int | None = Field(default=None, gt=0, le=30 * 24 * 60 * 60)
    claims: dict[str, Any] = Field(default_factory=dict)

    @field_validator("sub", "username", "aud", "kid")
    @classmethod
    def reject_blank_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise ValueError("must not be empty")
        return stripped

    @field_validator("claims", mode="before")
    @classmethod
    def claims_must_be_object(cls, value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError("claims must be a JSON object")
        return value

    @model_validator(mode="after")
    def subjects_agree(self) -> Self:
        if self.sub is not None and self.username is not None and self.sub != self.username:
            raise ValueError("sub and username must match when both are provided")
        return self

    def subject(self) -> str:
        return self.sub or self.username or "test-user"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    expired: bool
    exp: int
    kid: str
    key_status: KeyStatus
    alg: str


class CreateKeyRequest(BaseModel):
    """Optional window for a manually created key.

    Omit both timestamps to activate the key immediately for one lifetime.
    A ``not_before`` in the future yields a pending key. An ``expires_at``
    in the past yields an already expired key.
    """

    lifetime_seconds: int | None = Field(default=None, gt=0, le=365 * 24 * 60 * 60)
    not_before: datetime | None = None
    expires_at: datetime | None = None


class KeyMetadata(BaseModel):
    kid: str
    alg: str
    status: KeyStatus
    created_at: datetime
    not_before: datetime
    expires_at: datetime
    revoked: bool
    jwk: dict[str, str] = Field(description="Public JWK. Private parameters are never included.")


class JWKSResponse(BaseModel):
    keys: list[dict[str, str]]


class KeyNotFoundError(Exception):
    """Raised when a caller names a kid that is not in the store."""

    def __init__(self, kid: str) -> None:
        self.kid = kid
        super().__init__(f"Unknown key id '{kid}'")


class KeySelectionError(Exception):
    """Raised when key-selection parameters cannot be satisfied."""


class NoActiveKeyError(KeySelectionError):
    """Raised when a normal token was requested and every key is unusable."""


class TokenRequestError(Exception):
    """Raised when the token request itself is invalid."""
