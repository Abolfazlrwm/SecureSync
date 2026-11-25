# Scripts

Small operational scripts that don't belong in `Makefile` targets directly
(either because they're multi-step, or because `make` isn't installed on
every contributor's machine, e.g. some Windows setups).

Currently empty; scripts are added here when a task outgrows the
Makefile. Every script here must be **idempotent** and **safe to
re-run** — none of them should assume a pristine environment.
