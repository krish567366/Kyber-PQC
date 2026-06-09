import unittest
from concurrent.futures import ThreadPoolExecutor

from kyber_pqc.core import (
    Ciphertext,
    KyberKeyPair,
    decapsulate,
    encapsulate,
    generate_keypair,
    native_backend,
)


class TestKyberCryptosystem(unittest.TestCase):
    def test_native_backend(self):
        backend = native_backend()
        self.assertTrue(backend.startswith("kyber-pqc-native"))

    def test_full_exchange(self):
        for _ in range(10):
            kp = generate_keypair()
            ct = encapsulate(kp.public_key)
            self.assertIsInstance(ct, Ciphertext)
            recovered = decapsulate(ct.data, kp.private_key)
            self.assertEqual(recovered, ct.shared_secret)

    def test_error_handling(self):
        with self.assertRaises(ValueError):
            encapsulate(b"invalid_key")

        kp = generate_keypair()
        ct = encapsulate(kp.public_key)
        with self.assertRaises(ValueError):
            decapsulate(ct.data[:100], kp.private_key)

    def test_concurrent_safety(self):
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(generate_keypair) for _ in range(100)]
            results = [f.result() for f in futures]

        self.assertEqual(len(results), 100)
        self.assertEqual(len({kp.public_key for kp in results}), 100)
        for kp in results:
            self.assertIsInstance(kp, KyberKeyPair)


class TestMemorySafety(unittest.TestCase):
    def test_key_material_is_bytes(self):
        kp = generate_keypair()
        self.assertIsInstance(kp.public_key, bytes)
        self.assertIsInstance(kp.private_key, bytes)
        self.assertEqual(len(kp.public_key), 800)
        self.assertEqual(len(kp.private_key), 1632)
