"""RSA key generation and RFC 7517 public JWK encoding."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def generate_rsa_keypair(key_size: int) -> tuple[str, str]:
    """Return PKCS8 private PEM and SubjectPublicKeyInfo public PEM."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_pem, public_pem


def validate_keypair(private_pem: str, public_pem: str) -> None:
    """Reject material that is not an RSA pair, or a pair that does not match."""
    try:
        private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
        public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise ValueError("Key material is not valid PEM") from exc
    if not isinstance(private_key, RSAPrivateKey) or not isinstance(public_key, RSAPublicKey):
        raise ValueError("Key material is not an RSA key")
    if private_key.public_key().public_numbers() != public_key.public_numbers():
        raise ValueError("Public key does not match the private key")


def public_jwk(public_pem: str, *, kid: str, alg: str) -> dict[str, str]:
    """Encode an RSA public key as a JWK.

    ``n`` and ``e`` are base64url unsigned integers with the minimum number of
    octets and no padding, as required by RFC 7518.
    """
    public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    if not isinstance(public_key, RSAPublicKey):
        raise ValueError("Public key is not an RSA key")
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": alg,
        "kid": kid,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


def _b64url_uint(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
