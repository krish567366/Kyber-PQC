"""
Kyber-PQC Core Module: Native ML-KEM-512 implementation.

All cryptographic operations execute in the compiled C extension built from
the in-tree Kyber-512 reference core (not third-party Python wrappers).
"""

from typing import NamedTuple

from . import _native

PUBLIC_KEY_BYTES = 800
PRIVATE_KEY_BYTES = 1632
CIPHERTEXT_BYTES = 768
SHARED_SECRET_BYTES = 32


class SecurityError(Exception):
    """Raised when a cryptographic integrity check fails."""


class KyberKeyPair(NamedTuple):
    """Kyber-512 key pair."""

    public_key: bytes
    private_key: bytes


class Ciphertext(NamedTuple):
    """Kyber-512 ciphertext with derived shared secret."""

    data: bytes
    shared_secret: bytes


def native_backend() -> str:
    """Return the active native implementation backend."""
    return str(_native.backend_name())


def generate_keypair() -> KyberKeyPair:
    """Generate a new Kyber-512 key pair."""
    public_key, private_key = _native.keypair()
    return KyberKeyPair(public_key, private_key)


def encapsulate(public_key: bytes) -> Ciphertext:
    """Encapsulate a shared secret against a Kyber-512 public key."""
    if len(public_key) != PUBLIC_KEY_BYTES:
        raise ValueError(
            "Invalid public key length: "
            f"expected {PUBLIC_KEY_BYTES}, got {len(public_key)}"
        )

    ciphertext, shared_secret = _native.encapsulate(public_key)
    return Ciphertext(ciphertext, shared_secret)


def decapsulate(ciphertext: bytes, private_key: bytes) -> bytes:
    """Recover the shared secret from a ciphertext and private key."""
    if len(ciphertext) != CIPHERTEXT_BYTES:
        raise ValueError(
            "Invalid ciphertext length: "
            f"expected {CIPHERTEXT_BYTES}, got {len(ciphertext)}"
        )
    if len(private_key) != PRIVATE_KEY_BYTES:
        raise ValueError(
            "Invalid private key length: "
            f"expected {PRIVATE_KEY_BYTES}, got {len(private_key)}"
        )

    try:
        shared_secret = _native.decapsulate(ciphertext, private_key)
    except RuntimeError as exc:
        raise SecurityError("Decapsulation failed integrity check") from exc

    if len(shared_secret) != SHARED_SECRET_BYTES:
        raise SecurityError("Decapsulation produced an invalid shared secret")

    return shared_secret
