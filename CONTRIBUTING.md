# Contributing to SecureSync

Thank you for considering a contribution. This document describes how the
project is developed day to day.

## Development workflow

SecureSync is built phase by phase (see [ROADMAP.md](ROADMAP.md)). Each
phase corresponds to one cohesive module (filesystem watcher, chunk engine,
transfer engine, etc.) and is merged only once it is fully implemented,
tested, and documented.

1. **Open an issue first** for anything beyond a trivial fix — bug reports
   use the *Bug report* template, proposals use the *Feature request*
   template (see `.github/ISSUE_TEMPLATE/`).
2. **Fork and branch** from `main`. Branch naming: `phase/<n>-<short-name>`
   for roadmap work, `fix/<short-name>` for bug fixes, `docs/<short-name>`
   for documentation-only changes.
3. **Write the code, then the tests, then the docs** for the module you
   touched — a change is not "done" until all three are updated.
4. **Run the full local check suite** before opening a PR (see below).
5. **Open a pull request** using the PR template. Link the issue it closes.

## Local setup

```bash
git clone https://github.com/<org>/securesync.git
cd securesync
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Required checks

All four must pass before a PR is merged (the CI workflow enforces this):

```bash
make lint        # ruff
make format-check # black --check
make typecheck   # mypy --strict
make test        # pytest with coverage
```

See [docs/development.md](docs/development.md) for the full local
development guide.

## Coding standards

- **Type hints are mandatory** on every function/method signature — the
  codebase is checked with `mypy --strict`.
- **Docstrings are mandatory** on every public module, class, and function
  (Google-style).
- **No dependency violates the architecture layering** described in
  [docs/architecture.md](docs/architecture.md) — `domain/` never imports
  from `infrastructure/`, `presentation/`, or third-party I/O libraries.
- **New cryptographic code is not accepted** unless it composes primitives
  from the `cryptography` (pyca) library — no hand-rolled cryptography, ever.
  See [docs/security.md](docs/security.md).
- **Every new port (interface) added to `domain/` needs at least one fake
  adapter in `tests/`** so use cases can be tested without real I/O.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

feat(watcher): add debounce for rapid successive file writes
fix(chunker): correct off-by-one in rolling hash window
docs(protocol): document packet header CRC algorithm
test(transfer): add resume-after-disconnect integration test
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`.

## Architecture Decision Records

Any change to the architecture, a technology choice, or a security-relevant
design decision should be accompanied by a new file in `docs/adr/`,
numbered sequentially. See existing ADRs for the expected format.

## Code of Conduct

Participation in this project is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security issues

Do **not** open a public issue for a security vulnerability. See
[SECURITY.md](SECURITY.md) for the private reporting process.
