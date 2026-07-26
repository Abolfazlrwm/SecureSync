# Documentation Plan

Tracks every documentation artifact the project commits to maintaining, and
which phase first introduces real content into it.

| File | Purpose | Design content delivered | Verified against real implementation |
|---|---|---|---|
| `README.md` | Project overview, entry point for new visitors | Phase 0 / 0.5 | Grows every phase |
| `docs/architecture.md` | Clean Architecture layers, SOLID/patterns, tech decisions, diagrams | Phase 0 / 0.5 | Updated every phase |
| `docs/networking.md` | Peer discovery, connection lifecycle, heartbeat/reconnect | Phase 0.5 | Phase 4–5 |
| `docs/protocol.md` | Binary wire protocol: header layout, packet types, versioning | Phase 0.5 | Phase 5 |
| `docs/security.md` | Threat model, cryptographic decisions, attack mitigations | Phase 0.5 | Phase 6 |
| `docs/performance.md` | Benchmark methodology (results come later) | Phase 0.5 | Phase 2 ✅ (hashing + chunking populated); more benchmarks each phase after |
| `docs/development.md` | Local dev setup, running tests, lint/type-check workflow | Phase 0.5 | N/A — accurate now |
| `docs/deployment.md` | Running SecureSync as a service, Docker usage | Phase 0.5 | Phase 5+ |
| `docs/configuration.md` | YAML schema, environment variables, hot reload behavior | Phase 0.5 | Phase 10 |
| `docs/troubleshooting.md` | Common issues and diagnostics | Phase 0.5 (structure only) | Ongoing, populated as issues surface |
| `docs/adr/*` | Architecture Decision Records — one file per significant decision | 8 ADRs as of Phase 2 | One more per future notable decision |
| `CHANGELOG.md` | Keep-a-Changelog format, one entry set per phase | Phase 0 onward | — |
| `SECURITY.md` | Vulnerability reporting process + summary threat model | Phase 0.5 | Phase 6 (technical detail cross-check) |
| `CONTRIBUTING.md` | How to propose changes, coding standards, commit conventions | Phase 0.5 | — |
| `CODE_OF_CONDUCT.md` | Community conduct expectations | Phase 0.5 | — |

Every doc above marked "Phase 0.5" is a **design document** — it describes
the target behavior before the corresponding code exists. The
"Verified against real implementation" column tracks when each doc gets
its next pass, cross-checked against the actual working code for that
module, and corrected if the implementation diverged from the plan.

## Architecture Decision Records (ADRs)

Stored under `docs/adr/`, numbered sequentially (`0001-...md`). Five ADRs
(`0001`–`0005`) were written during Phase 0/0.5, covering Clean
Architecture, the async runtime, the cryptography library, the wire
protocol design, and the metadata store. ADR `0006`, added in Phase 1,
records the decision to build a port/adapter boundary around the
filesystem watcher rather than depending on `watchdog` directly
throughout the codebase. ADRs `0007` and `0008`, added in Phase 2, record
the chunk engine's `ChunkingStrategy` Strategy-pattern port (reserving
content-defined chunking for later without a breaking change) and its
synchronous core with an `async`-use-case boundary via `asyncio.to_thread`.
