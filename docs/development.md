# Development

## Prerequisites

- Python 3.12+
- `git`
- Optional: Docker + Docker Compose, for testing multi-peer scenarios
  locally without multiple machines

## Setup

```bash
git clone https://github.com/<org>/securesync.git
cd securesync
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

This installs SecureSync in editable mode plus all dev dependencies
(`pytest`, `mypy`, `ruff`, `black`, `pre-commit`) and registers the git
hooks defined in `.pre-commit-config.yaml`.

## Everyday commands

| Command | What it does |
|---|---|
| `make lint` | `ruff check` over `src/` and `tests/` |
| `make format` | Rewrites files with `black` |
| `make format-check` | `black --check` (what CI runs) |
| `make typecheck` | `mypy --strict` over `src/` |
| `make test` | Full `pytest` run |
| `make test-cov` | `pytest` with terminal + HTML coverage report |
| `make benchmark` | Runs `benchmarks/` (see `docs/performance.md`) |
| `make pre-commit` | Runs all pre-commit hooks against the whole repo |
| `make clean` | Removes caches and build artifacts |

## Project layout

See `docs/architecture.md` for the full explanation of *why* the codebase
is organized this way. Quick orientation:

```
src/securesync/
├── presentation/    # CLI + dashboard (Typer, Rich) — talks to application/
├── application/     # Use cases — orchestrates domain + infrastructure
├── domain/          # Entities, value objects, ports (interfaces). No I/O.
├── infrastructure/  # Concrete adapters: filesystem, network, db, crypto
├── core/             # Wire protocol, event bus, job scheduler
├── shared/           # Exceptions, common types, constants
├── config/           # YAML + env var loading and validation
└── utils/            # Small stateless helpers
```

## Testing conventions

- `tests/unit/` mirrors the `src/securesync/` package structure — a test
  for `domain/entities.py` lives at `tests/unit/domain/test_entities.py`.
- `tests/integration/` exercises multiple layers together (e.g. a use case
  with a real SQLite database in a temp directory).
- `tests/network/`, `tests/filesystem/`, `tests/chunking/`, `tests/security/`
  are for tests that specifically exercise those concerns end-to-end (real
  sockets, real filesystem events, real files at realistic scale,
  adversarial protocol inputs).
- `tests/property/` holds Hypothesis property-based tests — structural
  invariants checked against many randomly generated inputs, rather than
  the fixed set of examples in `tests/unit/`.
- `tests/benchmark/` holds correctness tests *for* the benchmark harness
  itself (not the benchmarks — those live in `benchmarks/`).
- Domain and application layer tests should never need a real socket, real
  filesystem, or real database — if a test needs one of those to exercise
  domain/application code, that's a signal a port is missing or leaking
  infrastructure details.

## Debugging tips

- The filesystem watcher (`infrastructure/filesystem/watchdog_watcher.py`)
  logs structured events via `structlog`. Set `structlog`'s log level to
  `DEBUG` to see every raw event, including ones suppressed by
  debouncing (`event_debounced`) or unrecognized by the translator
  (`unrecognized_watchdog_event`).
- On Linux, `watchdog` uses `inotify`, which has a per-user watch limit
  (`fs.inotify.max_user_watches`). Watching very large directory trees
  recursively can hit this; the symptom is silently missing events, not
  an exception. Check `cat /proc/sys/fs/inotify/max_user_watches` if
  events seem to stop arriving for deeply nested paths.
- `WatchdogFileWatcher` dispatches events from a background OS thread
  into the asyncio event loop via `asyncio.run_coroutine_threadsafe`. If
  you're debugging a hang or a missed event, check that the loop passed
  implicitly via `asyncio.get_running_loop()` at `start()` time is the
  same loop your test/application is actually running on.
- A single filesystem operation often produces more than one raw
  `watchdog` notification (e.g. a file write also touches the parent
  directory's mtime). Don't assume "one write = one event" when writing
  new tests — see `tests/filesystem/` for the predicate-based waiting
  pattern (`CollectingObserver.wait_until`) used to avoid that trap.
- `StreamingChunkReader` (`infrastructure/chunking/streaming_chunk_reader.py`)
  reads in bounded blocks regardless of chunk size — if you're debugging
  unexpected memory growth while chunking a large file, confirm the
  growth is actually coming from your own code holding onto `Chunk`
  objects (e.g. accumulating a list of them) rather than the reader
  itself; the reader only ever holds one chunk's worth of data at a time.
  `tests/chunking/test_streaming_chunk_reader_filesystem.py`'s
  `TestPeakMemoryStaysBounded` shows the `tracemalloc` pattern used to
  verify this.
- Chunk IDs are deterministic (derived from the source path and index via
  `uuid.uuid5`, not random) — if a chunk ID looks wrong, check the
  *inputs* to `_derive_chunk_id` first (has the path changed? the index?)
  rather than assuming non-determinism.
- The chunk engine's domain and infrastructure code is synchronous by
  design (see ADR-0008); only the use cases in `application/use_cases/`
  are `async`. If you're adding a new synchronous helper that an async
  use case needs to call without blocking the event loop, reach for
  `utils.async_iter.iter_in_thread` (for a blocking iterator) or
  `asyncio.to_thread` directly (for a single blocking call) rather than
  making the helper itself `async def` over a blocking implementation.

## Working across phases

Each roadmap phase (`ROADMAP.md`) is developed on its own branch and merged
as a complete, tested, documented unit — avoid mixing code from two
different phases in one PR.
