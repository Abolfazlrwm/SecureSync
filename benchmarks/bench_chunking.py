"""Benchmark: chunking throughput (`StreamingChunkReader` + `FixedSizeChunkingStrategy`).

Run directly:

    python -m benchmarks.bench_chunking            # smoke set (fast)
    python -m benchmarks.bench_chunking --full      # full set (slow, thorough)

Or via the whole suite: `python -m benchmarks` (see `benchmarks/__main__.py`).

Methodology (docs/performance.md §3): median of N runs plus p95, against
synthetic data of representative sizes. Chunking, unlike hashing, is
measured against a real file on a real filesystem (`StreamingChunkReader`
only reads real files by design), so the 10GB data point genuinely
writes 10GB to disk. If insufficient disk space is available, that size
is skipped with a clear message rather than failing partway through
file generation.
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from benchmarks._common import (
    FULL_RUNS,
    FULL_SIZES,
    SMOKE_RUNS,
    SMOKE_SIZES,
    BenchmarkResult,
    has_disk_space_for,
    measure,
    print_results,
    save_results,
    write_synthetic_file,
)
from securesync.infrastructure.chunking.streaming_chunk_reader import (
    FixedSizeChunkingStrategy,
    StreamingChunkReader,
)

#: Chunk size used throughout — matches the chunk engine's documented default.
_CHUNK_SIZE = 4 * 1024 * 1024


def run(sizes: dict[str, int], runs: int, work_dir: Path) -> list[BenchmarkResult]:
    """Benchmark `StreamingChunkReader.read_chunks` across `sizes`.

    Args:
        sizes: Mapping of display label to file size in bytes.
        runs: How many timed repetitions per size.
        work_dir: Scratch directory for the generated benchmark files.

    Returns:
        One `BenchmarkResult` per size that had enough disk space to
        run; sizes that didn't fit are skipped with a printed notice.
    """
    reader = StreamingChunkReader()
    strategy = FixedSizeChunkingStrategy(chunk_size=_CHUNK_SIZE)
    results = []

    for label, size_bytes in sizes.items():
        if not has_disk_space_for(size_bytes, at=work_dir):
            print(f"Skipping {label}: not enough free disk space at {work_dir}")
            continue

        target = work_dir / f"chunking_input_{label}.bin"
        write_synthetic_file(target, size_bytes)

        def _chunk_the_file(target: Path = target) -> None:
            for _ in reader.read_chunks(target, strategy):
                pass

        results.append(measure(label, size_bytes, _chunk_the_file, runs=runs))
        target.unlink(missing_ok=True)

    return results


def main(argv: list[str] | None = None) -> None:
    """CLI entry point: run the chunking benchmark and report results.

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
    with tempfile.TemporaryDirectory(prefix="securesync-bench-") as work_dir:
        results = run(sizes, runs, Path(work_dir))

    print_results("bench_chunking", results)
    output_path = save_results("bench_chunking", results)
    print(f"\nResults written to {output_path}")


if __name__ == "__main__":
    main()
