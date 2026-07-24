# Benchmarks

This directory holds SecureSync's benchmark suite. See
[`docs/performance.md`](../docs/performance.md) for the full methodology —
what's measured, how, and why.

**Status:** empty scaffold (Phase 0/0.5). Benchmark scripts are added starting
Phase 2 (Chunk Engine), one per module, as that module lands.

## Running (once populated)

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
