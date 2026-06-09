"""Hex-encoded PEM serialization for Kyber-512 material."""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from typing import Union

from .core import (
    CIPHERTEXT_BYTES,
    PRIVATE_KEY_BYTES,
    PUBLIC_KEY_BYTES,
    SHARED_SECRET_BYTES,
)

PEM_LINE_WIDTH = 64


class PEMKind(str, Enum):
    PUBLIC_KEY = "PUBLIC KEY"
    PRIVATE_KEY = "PRIVATE KEY"
    CIPHERTEXT = "CIPHERTEXT"
    SHARED_SECRET = "SHARED SECRET"


_EXPECTED_BYTES = {
    PEMKind.PUBLIC_KEY: PUBLIC_KEY_BYTES,
    PEMKind.PRIVATE_KEY: PRIVATE_KEY_BYTES,
    PEMKind.CIPHERTEXT: CIPHERTEXT_BYTES,
    PEMKind.SHARED_SECRET: SHARED_SECRET_BYTES,
}


def _header(kind: PEMKind) -> str:
    return f"-----BEGIN KYBER512 {kind.value}-----"


def _footer(kind: PEMKind) -> str:
    return f"-----END KYBER512 {kind.value}-----"


def encode_pem(kind: PEMKind, data: bytes) -> str:
    """Encode binary Kyber material as a hex PEM block."""
    expected = _EXPECTED_BYTES[kind]
    if len(data) != expected:
        raise ValueError(
            f"invalid data length for {kind.value}: "
            f"expected {expected}, got {len(data)}"
        )

    hex_body = data.hex()
    lines = [
        hex_body[i: i + PEM_LINE_WIDTH]
        for i in range(0, len(hex_body), PEM_LINE_WIDTH)
    ]
    return "\n".join([_header(kind), *lines, _footer(kind), ""])


def decode_pem(kind: PEMKind, pem: str) -> bytes:
    """Decode a hex PEM block back to binary Kyber material."""
    expected = _EXPECTED_BYTES[kind]
    begin = re.escape(_header(kind))
    end = re.escape(_footer(kind))
    match = re.search(
        rf"{begin}\s*([0-9a-fA-F\s]+?)\s*{end}",
        pem,
        flags=re.DOTALL,
    )
    if match is None:
        raise ValueError(f"missing or invalid PEM block for {kind.value}")

    body = re.sub(r"\s+", "", match.group(1))
    try:
        decoded = bytes.fromhex(body)
    except ValueError as exc:
        raise ValueError(f"invalid hex payload for {kind.value}") from exc

    if len(decoded) != expected:
        raise ValueError(
            f"invalid decoded length for {kind.value}: "
            f"expected {expected}, got {len(decoded)}"
        )
    return decoded


def write_pem_file(
    path: Union[str, Path],
    kind: PEMKind,
    data: bytes,
) -> None:
    """Write a hex PEM file with restrictive permissions."""
    pem_path = Path(path)
    pem_path.write_text(encode_pem(kind, data), encoding="utf-8")
    pem_path.chmod(0o600)


def read_pem_file(path: Union[str, Path], kind: PEMKind) -> bytes:
    """Read binary Kyber material from a hex PEM file."""
    return decode_pem(kind, Path(path).read_text(encoding="utf-8"))
