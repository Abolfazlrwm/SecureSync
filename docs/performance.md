# Performance

> Status: **Plan** — no benchmark results exist yet because no implementation
> code has been written (Phase 0). This document defines *how* SecureSync
> will be measured, so every phase from Phase 1 onward reports numbers
> against the same methodology instead of ad-hoc measurements.

## 1. Non-functional targets (carried over from `docs/architecture.md`)

- Never load a full file into memory — all file I/O is streamed, chunk by
  chunk, so memory usage should stay roughly constant regardless of file
  size (targeting files up to and beyond 100GB).
- All network and filesystem I/O is `async` — a single SecureSync process
  should be able to service many concurrent peer connections and file
  operations without one slow peer blocking others.

## 2. Metrics tracked, and where they're introduced

| Metric | Introduced in | Measured by |
|---|---|---|
| Hashing speed (MB/s) | Phase 2 (Chunk Engine) | `benchmarks/bench_hashing.py` |
| Chunking throughput (chunks/sec, MB/s) | Phase 2 | `benchmarks/bench_chunking.py` |
| Delta computation time | Phase 3 (Delta Sync) | `benchmarks/bench_delta.py` |
| Transfer speed (MB/s, LAN) | Phase 5 (Transfer Engine) | `benchmarks/bench_transfer.py` |
| Encryption/decryption speed (MB/s), AES-GCM vs ChaCha20-Poly1305 | Phase 6 | `benchmarks/bench_crypto.py` |
| End-to-end sync latency (small file, large file, many small files) | Phase 5–6 | `benchmarks/bench_e2e_sync.py` |
| Memory usage (RSS) under a 100GB file transfer | Phase 5 | `benchmarks/bench_memory.py` (profiled via `tracemalloc` / `memray`) |
| CPU usage under sustained sync | Phase 5–6 | `benchmarks/bench_cpu.py` |

## 3. Methodology

- Every benchmark reports **median of N=10 runs** plus p95, not a single
  sample — single-run numbers are noise, especially for network transfer.
- Benchmarks run in CI on every PR that touches a benchmarked module, but
  only as a smoke test (few iterations, generous thresholds); the full
  benchmark suite with statistically meaningful sample sizes runs on a
  schedule (nightly) and before releases.
- Hashing/chunking/crypto benchmarks run against synthetic data of
  representative sizes: 1KB, 1MB, 100MB, 10GB (streamed, not materialized).
- Transfer benchmarks run between two SecureSync instances on the same
  machine (loopback) *and* two containers on the `docker-compose.yml`
  bridge network, to separate "algorithmic" overhead from real network
  conditions.
- Regressions beyond a defined threshold (initially: 15%) versus the last
  release fail the nightly benchmark job and open a tracking issue
  automatically — this is configured once the benchmark suite exists
  (Phase 2 onward), not in Phase 0.

## 4. Reporting

Each phase's PR that introduces a new benchmark includes a "Benchmark
results" section in `CHANGELOG.md` with the measured numbers and the
machine/environment they were taken on (exact numbers are meaningless
without that context).

## 5. Directory layout (established now, populated starting Phase 2)

```
benchmarks/
├── __main__.py        # `python -m benchmarks` entry point (make benchmark)
├── bench_hashing.py
├── bench_chunking.py
├── bench_delta.py
├── bench_transfer.py
├── bench_crypto.py
├── bench_e2e_sync.py
├── bench_memory.py
├── bench_cpu.py
└── results/            # gitignored — local benchmark output
```

See `benchmarks/README.md` for how to run the suite once it exists.
