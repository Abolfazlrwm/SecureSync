"""`python -m benchmarks` — runs every registered benchmark in sequence.

See `benchmarks/README.md` for usage and `docs/performance.md` for the
methodology every benchmark here follows.
"""

from __future__ import annotations

import argparse

from benchmarks import bench_chunking, bench_hashing

#: Every benchmark module registered with the suite, in run order. Add
#: a new `bench_<module>.py` here so `make benchmark` picks it up (see
#: `benchmarks/README.md` "Adding a new benchmark"). Each module must
#: expose `main(argv: list[str] | None = None) -> None`.
_BENCHMARKS = (bench_hashing, bench_chunking)


def main() -> None:
    """Run every registered benchmark, passing `--full` through to each."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run the complete size set (slow) instead of the smoke set, for every benchmark.",
    )
    args = parser.parse_args()

    forwarded_argv = ["--full"] if args.full else []
    for module in _BENCHMARKS:
        module.main(forwarded_argv)


if __name__ == "__main__":
    main()
