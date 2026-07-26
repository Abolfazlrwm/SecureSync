"""Shared utilities for `benchmarks/bench_*.py` scripts.

Not a benchmark itself — internal support code implementing the
methodology defined in `docs/performance.md`: median of N runs plus
p95, peak/average memory via `tracemalloc`, and a smoke-vs-full size
split so CI can run a fast subset while a scheduled job runs the
complete one.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import time
import tracemalloc
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

#: Sizes used for the fast "smoke" run (CI, every PR touching a benchmarked module).
SMOKE_SIZES: dict[str, int] = {"1KB": 1024, "1MB": 1024 * 1024}

#: Sizes used for the complete run (scheduled/nightly, before releases) — see
#: docs/performance.md §3 for why these specific sizes were chosen.
FULL_SIZES: dict[str, int] = {
    "1KB": 1024,
    "1MB": 1024 * 1024,
    "100MB": 100 * 1024 * 1024,
    "10GB": 10 * 1024 * 1024 * 1024,
}

#: Runs per size for the smoke set — few iterations, per docs/performance.md §3.
SMOKE_RUNS = 3

#: Runs per size for the full set — statistically meaningful, per docs/performance.md §3.
FULL_RUNS = 10

RESULTS_DIR = Path(__file__).parent / "results"


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    """One size's worth of measurements for one benchmark."""

    label: str
    size_bytes: int
    runs: int
    median_seconds: float
    p95_seconds: float
    min_seconds: float
    max_seconds: float
    throughput_mb_per_s: float
    peak_memory_bytes: int
    average_peak_memory_bytes: float
    traced_allocation_count: int


def measure(label: str, size_bytes: int, fn: Callable[[], None], *, runs: int) -> BenchmarkResult:
    """Run `fn` `runs` times, timing and memory-profiling each run.

    Args:
        label: A human-readable name for this data point (e.g. `"1MB"`).
        size_bytes: The logical data volume `fn` processes, used to
            compute throughput. Not necessarily equal to any single
            allocation's size.
        fn: The operation to benchmark. Called with no arguments.
        runs: How many times to repeat `fn`.

    Returns:
        Aggregated timing and memory statistics across every run.
    """
    durations: list[float] = []
    peak_memories: list[int] = []
    traced_allocation_count = 0

    for _ in range(runs):
        tracemalloc.start()
        start = time.perf_counter()
        fn()
        elapsed = time.perf_counter() - start
        _current, peak = tracemalloc.get_traced_memory()
        snapshot = tracemalloc.take_snapshot()
        traced_allocation_count = sum(stat.count for stat in snapshot.statistics("filename"))
        tracemalloc.stop()

        durations.append(elapsed)
        peak_memories.append(peak)

    median_seconds = statistics.median(durations)
    throughput_mb_per_s = (
        (size_bytes / (1024 * 1024)) / median_seconds if median_seconds > 0 else 0.0
    )

    return BenchmarkResult(
        label=label,
        size_bytes=size_bytes,
        runs=runs,
        median_seconds=median_seconds,
        p95_seconds=_percentile(durations, 95),
        min_seconds=min(durations),
        max_seconds=max(durations),
        throughput_mb_per_s=throughput_mb_per_s,
        peak_memory_bytes=max(peak_memories),
        average_peak_memory_bytes=statistics.mean(peak_memories),
        traced_allocation_count=traced_allocation_count,
    )


def _percentile(values: list[float], percentile: float) -> float:
    """Nearest-rank percentile — no interpolation, adequate for N<=10 samples."""
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(percentile / 100 * (len(ordered) - 1))))
    return ordered[index]


def format_bytes(n: float) -> str:
    """Render a byte count in the largest whole unit that keeps it readable."""
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"  # pragma: no cover - unreachable for realistic sizes


def print_results(benchmark_name: str, results: list[BenchmarkResult]) -> None:
    """Print a plain-text table of results to stdout."""
    print(f"\n=== {benchmark_name} ===")
    header = (
        f"{'size':>8}  {'median':>10}  {'p95':>10}  {'throughput':>14}  "
        f"{'peak mem':>12}  {'avg peak mem':>14}  {'allocations':>12}"
    )
    print(header)
    print("-" * len(header))
    for result in results:
        print(
            f"{result.label:>8}  "
            f"{result.median_seconds * 1000:>9.2f}ms  "
            f"{result.p95_seconds * 1000:>9.2f}ms  "
            f"{result.throughput_mb_per_s:>11.2f}MB/s  "
            f"{format_bytes(result.peak_memory_bytes):>12}  "
            f"{format_bytes(result.average_peak_memory_bytes):>14}  "
            f"{result.traced_allocation_count:>12}"
        )


def save_results(benchmark_name: str, results: list[BenchmarkResult]) -> Path:
    """Write results as JSON under `benchmarks/results/` (gitignored)."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = RESULTS_DIR / f"{benchmark_name}.json"
    payload = [asdict(result) for result in results]
    output_path.write_text(json.dumps(payload, indent=2))
    return output_path


def write_synthetic_file(path: Path, size_bytes: int, block_size: int = 4 * 1024 * 1024) -> None:
    """Stream synthetic random data to `path` without materializing it all in memory.

    Args:
        path: Destination file, overwritten if it already exists.
        size_bytes: Total file size to generate.
        block_size: How much random data to generate and write per
            iteration — bounds peak memory during generation itself,
            independent of `size_bytes`.
    """
    remaining = size_bytes
    with path.open("wb") as file:
        while remaining > 0:
            n = min(block_size, remaining)
            file.write(os.urandom(n))
            remaining -= n


def has_disk_space_for(size_bytes: int, at: Path) -> bool:
    """Whether at least `size_bytes` (plus a safety margin) is free at `at`.

    Used to skip a large benchmark size gracefully in a constrained
    environment rather than failing partway through file generation
    with a disk-full error.
    """
    free_bytes = shutil.disk_usage(at).free
    safety_margin = size_bytes // 10  # require 10% headroom beyond the file itself
    return free_bytes >= size_bytes + safety_margin
