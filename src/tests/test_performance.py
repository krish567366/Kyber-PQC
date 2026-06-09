import unittest

from kyber_pqc.benchmark import benchmark_throughput
from kyber_pqc.core import encapsulate, generate_keypair


class TestPerformance(unittest.TestCase):
    def test_benchmark_throughput_smoke(self):
        results = benchmark_throughput(5)

        for operation in ("keygen", "encaps", "decaps"):
            self.assertIn(operation, results)
            self.assertGreater(results[operation]["mean_ops"], 0)

    def test_shared_secret_entropy_smoke(self):
        secrets = {
            encapsulate(generate_keypair().public_key).shared_secret
            for _ in range(50)
        }
        self.assertEqual(len(secrets), 50)
