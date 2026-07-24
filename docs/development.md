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
- `tests/network/`, `tests/filesystem/`, `tests/security/` are for tests
  that specifically exercise those concerns end-to-end (real sockets, real
  filesystem events, adversarial protocol inputs).
- `tests/benchmark/` holds correctness tests *for* the benchmark harness
  itself (not the benchmarks — those live in `benchmarks/`).
- Domain and application layer tests should never need a real socket, real
  filesystem, or real database — if a test needs one of those to exercise
  domain/application code, that's a signal a port is missing or leaking
  infrastructure details.

## Debugging tips

*(This section grows as real debugging workflows emerge — Phase 0 has no
runtime behavior to debug yet.)*

## Working across phases

Each roadmap phase (`ROADMAP.md`) is developed on its own branch and merged
as a complete, tested, documented unit — avoid mixing code from two
different phases in one PR.
