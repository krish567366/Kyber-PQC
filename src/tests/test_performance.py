# test_performance.py
def test_output_uniformity(self):
    """Validate shared secret randomness using NIST STS"""
    from Crypto.StatisticalTests import sts
    
    samples = b''.join(
        encapsulate(generate_keypair().public_key).shared_secret
        for _ in range(1_000_000)
    )
    
    p_value = sts.monobit_test(samples)
    self.assertGreater(p_value, 0.01)  # 99% confidence