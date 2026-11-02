"""Micro-benchmark for the v3 handshake primitives (design §5).

Measures the per-operation cost of each cryptographic primitive the
responder and initiator must compute during a v3 handshake, using the
same `cryptography` library the production code uses.

Methodology:
    * 5 runs of 2 000 iterations each (10 000 total per operation).
    * Report best (min), median, and p95 of per-iteration time.
    * A warm-up pass of 100 iterations is discarded before timing.
    * Run on a quiet machine — no other CPU-bound processes.

Usage::

    python -m benchmarks.bench_handshake
"""

from __future__ import annotations

import os
import statistics
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ITERATIONS = 2_000
RUNS = 5
WARMUP = 100


@dataclass(frozen=True, slots=True)
class TimingResult:
    """Aggregated timing for one operation across multiple runs."""

    label: str
    best_us: float
    median_us: float
    p95_us: float


def _percentile(values: list[float], percentile: float) -> float:
    """Nearest-rank percentile."""
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(percentile / 100 * (len(ordered) - 1))))
    return ordered[index]


def measure(
    label: str,
    fn: object,
    *,
    iterations: int = ITERATIONS,
    runs: int = RUNS,
) -> TimingResult:
    """Time ``fn`` ``iterations`` times per run, across ``runs`` runs.

    Each run produces one per-iteration median; the final result
    aggregates across runs.
    """
    # Warm-up — discard.
    for _ in range(WARMUP):
        fn()

    per_run_medians: list[float] = []

    for _run in range(runs):
        durations: list[float] = []
        for _ in range(iterations):
            start = time.perf_counter()
            fn()
            elapsed = time.perf_counter() - start
            durations.append(elapsed * 1e6)  # convert to microseconds
        per_run_medians.append(statistics.median(durations))

    return TimingResult(
        label=label,
        best_us=min(per_run_medians),
        median_us=statistics.median(per_run_medians),
        p95_us=_percentile(per_run_medians, 95),
    )


def _x25519_keygen() -> None:
    X25519PrivateKey.generate()


def _make_ecdh_pair() -> tuple[X25519PrivateKey, X25519PrivateKey]:
    a = X25519PrivateKey.generate()
    b = X25519PrivateKey.generate()
    return a, b


def _x25519_ecdh(pair: tuple[X25519PrivateKey, X25519PrivateKey]) -> None:
    a, b = pair
    a.exchange(b.public_key())


_FIXED_ED25519 = Ed25519PrivateKey.generate()
_FIXED_ED25519_PUB = _FIXED_ED25519.public_key()


def _ed25519_sign() -> None:
    _FIXED_ED25519.sign(b"benchmark-message-32-bytes!!!!!")  # noqa: S106


def _ed25519_verify() -> None:
    sig = _FIXED_ED25519.sign(b"benchmark-message-32-bytes!!!!!")  # noqa: S106
    _FIXED_ED25519_PUB.verify(sig, b"benchmark-message-32-bytes!!!!!")  # noqa: S106


_HKDF_INFO = b"securesync-1e-hkdf-info"
_HKDF_SALT = b"securesync-1e-hkdf-salt"


def _hkdf_sha256_32b() -> None:
    HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(os.urandom(32))


_HMAC_KEY = b"benchmark-hmac-key-32-bytes!!!!!!"  # noqa: S105


def _hmac_sha256_64b() -> None:
    h = HMAC(_HMAC_KEY, hashes.SHA256())
    h.update(b"x" * 64)
    h.finalize()


def main() -> None:
    """Run all measurements and print a table."""
    import platform

    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend

    print(f"Python {platform.python_version()} | {platform.platform()}")
    print(f"cryptography {cryptography.__version__} | {backend.openssl_version_text()}")
    print(f"Iterations: {ITERATIONS} x {RUNS} runs (warm-up: {WARMUP})\n")

    ecdh_pair = _make_ecdh_pair()

    operations: list[tuple[str, object]] = [
        ("X25519 keygen", _x25519_keygen),
        ("X25519 ECDH", lambda: _x25519_ecdh(ecdh_pair)),
        ("Ed25519 sign", _ed25519_sign),
        ("Ed25519 verify", _ed25519_verify),
        ("HKDF-SHA256 (32 B)", _hkdf_sha256_32b),
        ("HMAC-SHA256 (64 B)", _hmac_sha256_64b),
    ]

    results: list[TimingResult] = []
    for label, fn in operations:
        result = measure(label, fn)
        results.append(result)

    # Print table
    header = f"{'Operation':<25} {'Best (us)':>10} {'Median (us)':>12} {'p95 (us)':>10}"
    print(header)
    print("-" * len(header))
    for r in results:
        print(f"{r.label:<25} {r.best_us:>10.1f} {r.median_us:>12.1f} {r.p95_us:>10.1f}")

    # Compute derived totals from the BEST values
    best = {r.label: r.best_us for r in results}
    responder_best = (
        best["X25519 keygen"]
        + best["X25519 ECDH"]
        + best["Ed25519 sign"]
        + 2 * best["HKDF-SHA256 (32 B)"]
        + best["HMAC-SHA256 (64 B)"]
    )
    initiator_best = (
        best["Ed25519 verify"]
        + best["HKDF-SHA256 (32 B)"]
        + best["HMAC-SHA256 (64 B)"]
    )
    responder_median = sum(best[x] for x in ("X25519 keygen", "X25519 ECDH", "Ed25519 sign")) + (
        2 * best["HKDF-SHA256 (32 B)"] + best["HMAC-SHA256 (64 B)"]
    )
    initiator_median = (
        best["Ed25519 verify"] + best["HKDF-SHA256 (32 B)"] + best["HMAC-SHA256 (64 B)"]
    )

    print()
    print(f"Responder per message 1 (best):   {responder_best:.1f} us")
    print(f"Responder per message 1 (median): {responder_median:.1f} us")
    print(f"Initiator per message 2 (best):   {initiator_best:.1f} us")
    print(f"Initiator per message 2 (median): {initiator_median:.1f} us")

    # Worst-case (p95) for security assessment
    p95 = {r.label: r.p95_us for r in results}
    responder_p95 = (
        p95["X25519 keygen"]
        + p95["X25519 ECDH"]
        + p95["Ed25519 sign"]
        + 2 * p95["HKDF-SHA256 (32 B)"]
        + p95["HMAC-SHA256 (64 B)"]
    )
    print(f"\nResponder per message 1 (p95): {responder_p95:.1f} us")
    print(f"  -> At {responder_p95:.0f} us/msg1, 200/s global cap costs "
          f"{responder_p95 * 200 / 1000:.1f} ms/s")


if __name__ == "__main__":
    main()
