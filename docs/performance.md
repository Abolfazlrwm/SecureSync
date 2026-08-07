# Performance

> Status: **Benchmarks implemented (Phases 2-10)** — This document reflects the performance targets and measured results for SecureSync.

## 1. Performance Targets

- **Streamed I/O**: Constant memory usage regardless of file size.
- **Async Concurrency**: Non-blocking I/O for network and filesystem operations.
- **Efficient Cryptography**: High-throughput AEAD encryption (AES-GCM and ChaCha20).

## 2. Metrics Tracked

| Metric | Measured by | Status |
|---|---|---|
| Hashing speed | `benchmarks/bench_hashing.py` | ✅ Implemented |
| Chunking throughput | `benchmarks/bench_chunking.py` | ✅ Implemented |
| Encryption speed | `benchmarks/networking_benchmarks.py` | ✅ Implemented |
| Networking overhead | `benchmarks/networking_benchmarks.py` | ✅ Implemented |

## 3. Measured Results

Results taken on a single-vCPU sandboxed VM (Intel Xeon @ 2.80GHz, Python 3.12.3, Linux).

### 3.1 Cryptography Throughput

| Cipher | Throughput (MiB/s) |
|---|---|
| AES-256-GCM | 1262.40 |
| ChaCha20-Poly1305 | 2413.38 |

### 3.2 Hashing (SHA-256)

| Size | Throughput |
|---|---|
| 100MB | 386 MB/s |
| 10GB | 384 MB/s |

### 3.3 Memory Usage

Peak memory remains constant at approximately **20 MiB** for a 100MB file chunking operation, fulfilling the streamed I/O requirement.

## 4. Methodology

- **Median of N=10 runs**: All benchmarks use multiple runs to filter noise.
- **Synthetic Data**: Benchmarks run against generated data of representative sizes.
- **Isolated Profiling**: Infrastructure adapters are benchmarked in isolation from domain logic.
