"""
Throughput benchmarking for Kyber-512 operations.
"""

import statistics
import time
from typing import Callable, Dict, List, Sequence, TypeVar

from .core import decapsulate, encapsulate, generate_keypair

WARMUP_ITERATIONS = 10
CONFIDENCE_LEVEL = 0.99
T = TypeVar("T")


def benchmark_throughput(operations: int) -> Dict[str, Dict[str, float]]:
    """
    Measure key generation, encapsulation, and decapsulation throughput.

    Returns:
        Dictionary with mean operations/second and confidence intervals.
    """
    if operations < 1:
        raise ValueError("operations must be at least 1")

    keypairs = [generate_keypair() for _ in range(operations)]
    public_keys = [kp.public_key for kp in keypairs]
    ciphertexts = [encapsulate(pk) for pk in public_keys]

    return {
        "keygen": _analyze_results(
            _time_operation(generate_keypair, operations)
        ),
        "encaps": _analyze_results(
            _time_operation(
                lambda pk: encapsulate(pk),
                operations,
                public_keys,
            )
        ),
        "decaps": _analyze_results(
            _time_operation(
                lambda ct, sk: decapsulate(ct.data, sk),
                operations,
                list(
                    zip(
                        ciphertexts,
                        [kp.private_key for kp in keypairs],
                    )
                ),
            )
        ),
    }


def _time_operation(
    func: Callable[..., T],
    operations: int,
    inputs: Sequence = (),
) -> List[float]:
    """Return per-operation durations in seconds."""
    for _ in range(WARMUP_ITERATIONS):
        if inputs:
            item = inputs[0]
            if isinstance(item, tuple):
                func(*item)
            else:
                func(item)
        else:
            func()

    durations: List[float] = []
    if inputs:
        for item in inputs:
            item_start = time.perf_counter()
            if isinstance(item, tuple):
                func(*item)
            else:
                func(item)
            durations.append(time.perf_counter() - item_start)
    else:
        for _ in range(operations):
            item_start = time.perf_counter()
            func()
            durations.append(time.perf_counter() - item_start)

    return durations


def _analyze_results(durations: Sequence[float]) -> Dict[str, float]:
    """Compute throughput with a confidence interval."""
    if not durations:
        return {"mean_ops": 0.0, "confidence_interval": 0.0}

    mean_duration = statistics.mean(durations)
    if len(durations) < 2:
        return {"mean_ops": 1 / mean_duration, "confidence_interval": 0.0}

    stdev = statistics.stdev(durations)
    ci = statistics.NormalDist().inv_cdf((1 + CONFIDENCE_LEVEL) / 2)
    margin = (ci * stdev) / (len(durations) ** 0.5)

    return {
        "mean_ops": 1 / mean_duration,
        "confidence_interval": margin / mean_duration,
    }
