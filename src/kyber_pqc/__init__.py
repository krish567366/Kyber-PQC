"""
Kyber-PQC: Quantum-Resistant Cryptographic Framework

Exports:
- generate_keypair: Create new Kyber key pair
- encapsulate: Generate ciphertext and shared secret
- decapsulate: Recover shared secret from ciphertext
- benchmark_throughput: Performance analysis tool
"""

__version__ = "1.0.0"

from .core import (
    KyberKeyPair,
    Ciphertext,
    generate_keypair,
    encapsulate,
    decapsulate
)
from .benchmark import benchmark_throughput

__all__ = [
    'KyberKeyPair',
    'Ciphertext',
    'generate_keypair',
    'encapsulate',
    'decapsulate',
    'benchmark_throughput'
]