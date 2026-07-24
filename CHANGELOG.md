# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
