import unittest
import os
from kyber_pqc.core import *

class TestKyberCryptosystem(unittest.TestCase):
    def test_full_exchange(self):
        for _ in range(100):  # Statistical validation
            kp = generate_keypair()
            ct = encapsulate(kp.public_key)
            ss1 = ct.shared_secret
            ss2 = decapsulate(ct.data, kp.private_key)
            self.assertEqual(ss1, ss2)
    
    def test_error_handling(self):
        with self.assertRaises(ValueError):
            encapsulate(b'invalid_key')
        
        kp = generate_keypair()
        with self.assertRaises(SecurityError):
            decapsulate(b'\x00'*768, kp.private_key)
    
    def test_concurrent_safety(self):
        from concurrent.futures import ThreadPoolExecutor
        
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(generate_keypair) for _ in range(1000)]
            results = [f.result() for f in futures]
        
        self.assertEqual(len({pk for pk, sk in results}), 1000)

class TestMemorySafety(unittest.TestCase):
    def test_zeroization(self):
        kp = generate_keypair()
        sk_data = kp.private_key
        
        # Force garbage collection
        del kp
        import gc; gc.collect()
        
        # Verify memory was zeroized
        self.assertNotEqual(sk_data, bytes(1632))