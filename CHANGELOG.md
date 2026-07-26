# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added — Phase 2: Chunk Engine
- Streaming, bounded-memory file chunking and a SHA-256 hashing engine.
  Designed to process files far larger than available RAM (targeting
  100GB+) without ever loading a full file into memory — peak memory is
  bounded by chunk size, not file size (verified empirically in
  `tests/chunking/test_streaming_chunk_reader_filesystem.py` via
  `tracemalloc`, and in the benchmark results below).
- `domain/chunk.py`: `Chunk`, `ChunkHash`, `ChunkMetadata`,
  `ChunkCollection` (immutable value objects, `frozen`/`slots`
  dataclasses) and the `ChunkAlgorithm` enum.
- `domain/chunking.py`: the `ChunkingStrategy` port (Strategy pattern —
  see ADR-0007), and the `ChunkReader`, `ChunkHasher`, `ChunkWriter`,
  `ChunkRepository` ports. Pure Python; no I/O, no hashing library
  import.
- `domain/chunk_exceptions.py`: `ChunkingError` and friends
  (`InvalidChunkSizeError`, `ChunkSourceNotFoundError`,
  `ChunkSourceAccessError`, `ChunkVerificationError`).
- `shared/exceptions.py`: `ChunkEngineError`, the shared root for
  chunk-engine infrastructure failures with no domain meaning.
- `infrastructure/chunking/streaming_chunk_reader.py`:
  `FixedSizeChunkingStrategy` (default 4 MiB, configurable) and
  `StreamingChunkReader` — reads in bounded blocks (capped at 16 MiB
  regardless of configured chunk size), tolerant of short/interrupted
  `readinto()` reads, with deterministic (UUID5-derived) chunk IDs.
- `infrastructure/chunking/sha256_hash_provider.py`:
  `SHA256HashProvider` — `hashlib` only, feeds the hasher in bounded
  `memoryview` sub-blocks to avoid copying.
- `infrastructure/chunking/chunk_file_writer.py`: `ChunkFileWriter` —
  atomic writes (temp file + `fsync` + rename) with exception-safe
  cleanup on failure.
- `infrastructure/chunking/file_chunk_repository.py`:
  `FileChunkRepository` — a temporary filesystem-backed
  `ChunkRepository` (JSON manifest per file); the SQLite-backed
  implementation planned for Phase 8 will sit behind the same port.
- `application/use_cases/chunk_file.py`: `ChunkFileUseCase` — chunks
  and hashes a file, streaming.
- `application/use_cases/verify_chunk.py`: `VerifyChunkUseCase` —
  re-hashes a chunk and compares against its recorded hash.
- `application/use_cases/calculate_chunk_hashes.py`:
  `CalculateChunkHashesUseCase` — hashes a file's chunks without ever
  retaining chunk bytes; can build a full `ChunkCollection` manifest.
- `utils/async_iter.py`: `iter_in_thread`, a generic blocking-iterator-
  to-async-iterator bridge (see ADR-0008) — not chunk-engine-specific,
  reusable by any future phase with the same need.
- 147 new tests (258 total) across `tests/unit/`, `tests/chunking/`
  (real-filesystem, realistic scale), `tests/integration/`, and
  `tests/property/` (Hypothesis property-based tests). 98% coverage on
  `src/securesync/` (100% on every Phase 2 module; the only misses are
  unreachable abstract-method stubs, matching the Phase 1 baseline
  pattern).
- `benchmarks/_common.py`, `benchmarks/bench_hashing.py`,
  `benchmarks/bench_chunking.py`, `benchmarks/__main__.py`: the first
  populated benchmarks, per the methodology in `docs/performance.md`
  (median of N runs + p95, peak/average memory via `tracemalloc`, a
  smoke set for CI and a full set for scheduled runs). See "Benchmark
  results" below.
- `docs/adr/0007-chunking-strategy-as-a-pluggable-port.md`: why
  chunking-boundary decisions are a pluggable Strategy-pattern port,
  reserving content-defined chunking for a later phase without a
  breaking change.
- `docs/adr/0008-synchronous-chunk-engine-core-with-async-boundary.md`:
  why the chunk engine's domain/infrastructure layers are synchronous
  while its use cases stay `async`, bridged via `asyncio.to_thread`.
- `docs/architecture.md`, `docs/documentation-plan.md`, `ROADMAP.md`,
  `benchmarks/README.md` updated to reflect Phase 2 as implemented.

#### Benchmark results

Measured on a single-vCPU sandboxed VM (Intel Xeon @ 2.80GHz, Python
3.12.3, Linux) — see `docs/performance.md` §4: exact numbers are
meaningless without this context, and are expected to differ
(likely favorably) on real developer/CI hardware. Full methodology run
(`python -m benchmarks --full`); N=10 runs per size, median reported.

**Hashing** (`SHA256HashProvider`, 4 MiB buffer reused per call):

| Size | Median | Throughput | Peak memory |
|---|---|---|---|
| 1KB | 0.02ms | 57 MB/s | 1.6 KiB |
| 1MB | 2.72ms | 368 MB/s | 1.0 MiB |
| 100MB | 259ms | 386 MB/s | 696 B |
| 10GB | 26.6s | 384 MB/s | 696 B |

**Chunking** (`StreamingChunkReader`, real files, 4 MiB chunks):

| Size | Median | Throughput | Peak memory |
|---|---|---|---|
| 1KB | 0.43ms | 2.3 MB/s | 4.0 MiB |
| 1MB | 0.92ms | 1085 MB/s | 7.0 MiB |
| 100MB | 66.3ms | 1509 MB/s | 20.0 MiB |
| 10GB | *skipped: insufficient disk space in this environment (9.7GB free); `bench_chunking.py` detects this and skips gracefully rather than failing partway through file generation — see `has_disk_space_for` in `benchmarks/_common.py`.* | | |

Peak memory for both benchmarks stays within a small, roughly constant
range across four orders of magnitude of input size — the qualitative
property the design targets — rather than scaling with file size.

### Fixed — pre-implementation review (Phase 2)
- A first draft of `VerifyChunkUseCase` computed the hash synchronously
  on the calling coroutine before handing an already-computed value to
  the thread-offload helper, defeating the point of offloading it at
  all — caught while writing `tests/unit/application/use_cases/test_verify_chunk_use_case.py`;
  fixed to call `asyncio.to_thread(hasher.hash, data)` directly.
- `ChunkFileWriter`'s failure-cleanup path could itself raise
  (`NotADirectoryError` when the destination's parent isn't a real
  directory), masking the original write failure entirely — caught by
  `test_write_failure_error_chains_original_cause`; the cleanup is now
  wrapped in `contextlib.suppress(OSError)` so it can never raise a new
  exception that hides the one being reported to the caller.

### Added — Phase 1: Filesystem Watcher
- First real application code in the repository. Implements filesystem
  monitoring (create/modify/delete/move/rename), across multiple
  directories, optionally recursive, with debouncing of duplicate
  rapid-fire events, async dispatch, graceful shutdown, and a
  thread-safe Observer pattern — behind a domain port so no other layer
  depends on `watchdog` directly.
- `domain/events.py`: `FileSystemEvent` (immutable value object) and
  `FileSystemEventType` enum, including `is_rename` and `dedup_key`.
- `domain/watcher.py`: the `FileWatcher` port (subject) and the
  `FileSystemEventObserver` protocol (observer) — the Observer pattern
  boundary. Pure Python; no `watchdog` import.
- `domain/exceptions.py`: `WatcherError` and friends
  (`WatcherAlreadyRunningError`, `InvalidWatchTargetError`).
- `shared/exceptions.py`: `SecureSyncError` (base) and
  `FileWatcherError`, the shared root for cross-layer infrastructure
  failures.
- `infrastructure/filesystem/watchdog_watcher.py`: `WatchdogFileWatcher`,
  the `watchdog`-based `FileWatcher` adapter — the only module that
  imports `watchdog`.
- `infrastructure/filesystem/debounce.py`: thread-safe `EventDebouncer`
  with bounded memory (stale entries are evicted opportunistically, so a
  long-running watcher over a high-churn directory doesn't leak memory).
- `infrastructure/filesystem/event_translator.py`: pure translation from
  raw `watchdog` events to domain `FileSystemEvent` objects, plus
  `is_ignorable_event_type` so routine, in-scope noise (file open/close
  notifications) is logged at DEBUG rather than WARNING.
- `application/use_cases/monitor_directories.py`:
  `MonitorDirectoriesUseCase`, orchestrating the watcher's lifecycle and
  observer registration; usable as an `async with` context manager for
  guaranteed graceful shutdown.
- `application/observers/logging_observer.py`:
  `LoggingFileSystemEventObserver`, a minimal reference observer.
- 111 tests across `tests/unit/`, `tests/filesystem/` (real temp-directory,
  real OS-event tests), and `tests/integration/` (use case + real
  adapter). 98% coverage on `src/securesync/` (100% on every Phase 1
  module).
- `docs/adr/0006-filesystem-watcher-port-and-watchdog-adapter.md`: the
  decision record for the port/adapter split and the debounce/dispatch
  design.
- `docs/architecture.md` updated: `FileWatcher` added to the domain
  layer's port list, the Observer pattern entry marked implemented, a
  new Filesystem Watcher class diagram, and the `asyncio`/`watchdog`
  technology rows marked implemented.
- `docs/development.md`: real debugging tips for the watcher (inotify
  watch limits, structured logging, thread/event-loop interaction)
  replacing the Phase 0 placeholder.

### Fixed — Phase 0.5 audit (pre-Phase-1 design review)
- **Mermaid syntax bugs**: 12 instances of literal `\n` (rendered as text,
  not a line break) in `docs/networking.md` and `docs/deployment.md`
  corrected to `<br/>`; invalid dotted-arrow label syntax in
  `docs/architecture.md` corrected to the pipe-delimited form; a
  multi-parameter generic in the class diagram simplified to avoid
  ambiguous parsing.
- **CI would have failed on the first PR**: `pytest` exits with code 5
  ("no tests collected") since no tests exist before Phase 1 — verified by
  actually running it. `.github/workflows/ci.yml` and `Makefile`
  (`test`, `test-cov`) now explicitly tolerate that exit code as a pass,
  with a clear note that any *other* non-zero code still fails the build.
- **Stale status text**: README banner said "Phase 0" while the badge said
  "Phase 0.5"; the Configuration and FAQ sections said linked docs weren't
  "published yet" when they already existed. All corrected.
- **Inconsistent doc conventions**: `docs/development.md` and
  `docs/protocol.md` titles didn't match the plain single-word convention
  used by every sibling doc; `Status:` line formatting normalized across
  `docs/architecture.md` and `docs/troubleshooting.md`.
- **Version/config drift**: added the missing Python 3.13 classifier to
  `pyproject.toml` (CI already tested against it); deduplicated coverage
  flags repeated across `pyproject.toml`, `Makefile`, and CI into a single
  source of truth; documented that the `securesync` CLI entry point has no
  target module yet (added in Phase 9, by design).
- **Missing `.dockerignore`** — added, so the Docker build context excludes
  `.git`, caches, docs, and tests.
- **Stray/redundant `.gitkeep` files** removed from the repo root,
  `.github/`, `.github/workflows/`, and `tests/` (each already had real
  tracked content or tracked subdirectories, making the marker files dead
  weight).
- Verified (not just reviewed): zero broken local markdown links, zero
  orphaned files, all 9 Mermaid diagrams have balanced brackets and valid
  diagram-type declarations, all YAML/TOML files parse, the config schema
  in `docs/configuration.md` structurally matches
  `examples/config/peer-a.yaml`, and `ruff`/`black --check`/`mypy --strict`
  all pass cleanly against the current scaffold.

### Added — Phase 0.5: Repository & Documentation Polish
- Community health files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md`.
- Tooling config: `.editorconfig`, `.pre-commit-config.yaml`, `Makefile`.
- Deployment scaffolding: `Dockerfile`, `docker-compose.yml`.
- GitHub automation: `.github/workflows/ci.yml`, issue templates
  (bug report, feature request, config), `PULL_REQUEST_TEMPLATE.md`,
  `CODEOWNERS`.
- Full documentation set: `docs/networking.md`, `docs/protocol.md`,
  `docs/security.md` (full threat model), `docs/performance.md`
  (benchmark plan), `docs/development.md`, `docs/deployment.md`,
  `docs/configuration.md`, `docs/troubleshooting.md`.
- Five Architecture Decision Records (`docs/adr/0001`–`0005`) covering
  Clean Architecture, the async runtime, the cryptography library, the
  wire protocol design, and the metadata store.
- Class, package, and component diagrams added to `docs/architecture.md`;
  sequence diagrams added to `docs/protocol.md` and `docs/networking.md`;
  a network diagram in `docs/networking.md`; a deployment diagram in
  `docs/deployment.md`.
- `assets/logo.svg` (original mark) and `assets/README.md` tracking
  screenshot placeholders.
- `benchmarks/README.md` describing how the (not-yet-populated) benchmark
  suite will be run.
- Minimal `__init__.py` package markers under `src/securesync/` (no
  application logic — Phase 1 introduces the first real code).
- README expanded with a Documentation section, Community section, and
  updated badges.

### Added — Phase 0: Architecture & Scaffolding
- Clean Architecture layer structure (`presentation`, `application`,
  `domain`, `infrastructure`, `core`, `shared`, `config`, `utils`).
- Test directory structure (`unit`, `integration`, `network`,
  `filesystem`, `security`, `benchmark`).
- `pyproject.toml` with dependency and tooling decisions (ruff, black,
  mypy strict mode, pytest + pytest-asyncio + coverage).
- Initial `README.md` structure.
- `docs/architecture.md` describing layers, SOLID principles, design
  patterns, and technology decisions.
- `docs/documentation-plan.md` tracking every doc file and when it lands.
- `ROADMAP.md` covering Phases 0–10 and the advanced-feature backlog.
- `LICENSE` (MIT), `.gitignore`.
