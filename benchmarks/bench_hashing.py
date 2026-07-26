"""Benchmark: SHA-256 hashing throughput (`SHA256HashProvider`).

Run directly:

    python -m benchmarks.bench_hashing            # smoke set (fast)
    python -m benchmarks.bench_hashing --full      # full set (slow, thorough)

Or via the whole suite: `python -m benchmarks` (see `benchmarks/__main__.py`).

Methodology (docs/performance.md §3): median of N runs plus p95, against
synthetic data of representative sizes, streamed rather than
materialized. For hashing specifically, "streamed" means the benchmark
never allocates more than one chunk-sized buffer at once, even for the
"10GB" data point — it reuses a single pre-generated chunk-sized buffer
and hashes it repeatedly to reach the target volume, exactly mirroring
how `ChunkFileUseCase` actually calls the hasher in production (many
chunk-sized calls, never one call over the whole file). This also keeps
the benchmark's own random-number-generation cost out of the timed
region, so the reported number reflects hashing throughput alone.
"""

from __future__ import annotations

import argparse
import os

from benchmarks._common import (
    FULL_RUNS,
    FULL_SIZES,
    SMOKE_RUNS,
    SMOKE_SIZES,
    BenchmarkResult,
    measure,
    print_results,
    save_results,
)
from securesync.infrastructure.chunking.sha256_hash_provider import SHA256HashProvider

#: The buffer size reused for every hash() call — matches the chunk
#: engine's default chunk size, so throughput reflects realistic usage.
_HASH_BUFFER_SIZE = 4 * 1024 * 1024


def run(sizes: dict[str, int], runs: int) -> list[BenchmarkResult]:
    """Benchmark `SHA256HashProvider.hash` across `sizes`.

    Args:
        sizes: Mapping of display label to total logical bytes to hash.
        runs: How many timed repetitions per size.

    Returns:
        One `BenchmarkResult` per size, in the order given.
    """
    provider = SHA256HashProvider()
    buffer = os.urandom(_HASH_BUFFER_SIZE)
    results = []

    for label, total_size in sizes.items():

        def _hash_total_volume(total_size: int = total_size) -> None:
            remaining = total_size
            while remaining > 0:
                n = min(_HASH_BUFFER_SIZE, remaining)
                provider.hash(buffer if n == _HASH_BUFFER_SIZE else buffer[:n])
                remaining -= n

        results.append(measure(label, total_size, _hash_total_volume, runs=runs))

    return results


def main(argv: list[str] | None = None) -> None:
    """CLI entry point: run the hashing benchmark and report results.

    Args:
        argv: Arguments to parse instead of `sys.argv`, so
            `benchmarks/__main__.py` can invoke this programmatically
            when running the whole suite.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run the complete size set (slow) instead of the smoke set.",
    )
    args = parser.parse_args(argv)

    sizes, runs = (FULL_SIZES, FULL_RUNS) if args.full else (SMOKE_SIZES, SMOKE_RUNS)
    results = run(sizes, runs)
    print_results("bench_hashing", results)
    output_path = save_results("bench_hashing", results)
    print(f"\nResults written to {output_path}")


if __name__ == "__main__":
    main()
