# Scripts

Small operational scripts that don't belong in `Makefile` targets directly
(either because they're multi-step, or because `make` isn't installed on
every contributor's machine, e.g. some Windows setups).

**Status:** empty scaffold (Phase 0.5). Populated as each is actually
needed rather than pre-written speculatively.

| Planned script | Purpose | Added in |
|---|---|---|
| `bootstrap.sh` / `bootstrap.ps1` | One-shot environment setup for new contributors (venv + deps + pre-commit) | Phase 1, if `make install` proves insufficient cross-platform |
| `release.sh` | Version bump, changelog finalization, git tag | First tagged release |
| `gen-adr.sh` | Scaffold a new numbered ADR from the template in `docs/adr/README.md` | On demand |
| `check-layering.py` | Static check that `domain/` has no forbidden imports (see ADR 0001) | Phase 1, wired into CI |

Every script here must be **idempotent** and **safe to re-run** — none of
them should assume a pristine environment.
