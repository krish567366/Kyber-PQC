"""
Kyber-PQC: Kyber-512 Key Encapsulation for Python.

Exports:
- generate_keypair: Create a new Kyber-512 key pair
- encapsulate: Generate ciphertext and shared secret
- decapsulate: Recover shared secret from ciphertext
- benchmark_throughput: Performance analysis helper
"""

__version__ = "1.0.0"

from .benchmark import benchmark_throughput
from .pem import PEMKind, decode_pem, encode_pem, read_pem_file, write_pem_file
from .core import (
    native_backend,
    CIPHERTEXT_BYTES,
    PRIVATE_KEY_BYTES,
    PUBLIC_KEY_BYTES,
    SHARED_SECRET_BYTES,
    Ciphertext,
    KyberKeyPair,
    SecurityError,
    decapsulate,
    encapsulate,
    generate_keypair,
)

__all__ = [
    "CIPHERTEXT_BYTES",
    "Ciphertext",
    "KyberKeyPair",
    "PEMKind",
    "PRIVATE_KEY_BYTES",
    "PUBLIC_KEY_BYTES",
    "SHARED_SECRET_BYTES",
    "SecurityError",
    "benchmark_throughput",
    "decode_pem",
    "decapsulate",
    "encapsulate",
    "encode_pem",
    "generate_keypair",
    "native_backend",
    "read_pem_file",
    "write_pem_file",
]
