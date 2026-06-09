import tempfile
import unittest
from pathlib import Path

from kyber_pqc.core import encapsulate, generate_keypair
from kyber_pqc.pem import (
    PEMKind,
    decode_pem,
    encode_pem,
    read_pem_file,
    write_pem_file,
)


class TestPEM(unittest.TestCase):
    def test_round_trip(self):
        kp = generate_keypair()
        ct = encapsulate(kp.public_key)

        public_pem = encode_pem(PEMKind.PUBLIC_KEY, kp.public_key)
        decoded_public = decode_pem(PEMKind.PUBLIC_KEY, public_pem)
        self.assertEqual(decoded_public, kp.public_key)

        private_pem = encode_pem(PEMKind.PRIVATE_KEY, kp.private_key)
        self.assertEqual(
            decode_pem(PEMKind.PRIVATE_KEY, private_pem),
            kp.private_key,
        )

        cipher_pem = encode_pem(PEMKind.CIPHERTEXT, ct.data)
        self.assertEqual(decode_pem(PEMKind.CIPHERTEXT, cipher_pem), ct.data)

        secret_pem = encode_pem(PEMKind.SHARED_SECRET, ct.shared_secret)
        self.assertEqual(
            decode_pem(PEMKind.SHARED_SECRET, secret_pem),
            ct.shared_secret,
        )

    def test_file_round_trip(self):
        kp = generate_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "private.hex.pem"
            write_pem_file(path, PEMKind.PRIVATE_KEY, kp.private_key)
            self.assertEqual(oct(path.stat().st_mode & 0o777), oct(0o600))
            self.assertEqual(
                read_pem_file(path, PEMKind.PRIVATE_KEY),
                kp.private_key,
            )

    def test_invalid_length(self):
        with self.assertRaises(ValueError):
            encode_pem(PEMKind.PUBLIC_KEY, b"short")
