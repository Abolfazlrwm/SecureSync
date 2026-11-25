# Benchmarks

This directory holds SecureSync's benchmark suite. See
[`docs/performance.md`](../docs/performance.md) for the full methodology —
what's measured, how, and why.

**Status:** populated. `bench_hashing.py` and `bench_chunking.py` cover
the chunk engine; `bench_handshake.py` and `networking_benchmarks.py`
cover the handshake and transfer paths. A few committed result files
(`results_*.txt`) are kept for reference; they are snapshots from one
machine and should not be read as guarantees.

## Running

```bash
make benchmark
# or directly:
python -m benchmarks
```

Results are written to `benchmarks/results/` (gitignored — these are local,
machine-specific numbers, not committed).

## Adding a new benchmark

1. Add `bench_<module>.py` following the existing naming pattern.
2. Report median of at least 10 runs plus p95 — see
   `docs/performance.md` §3 for the required methodology.
3. Register it in `__main__.py` so `make benchmark` picks it up.
