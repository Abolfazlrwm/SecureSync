# Architecture Decision Records

Numbered sequentially, never renumbered or deleted (a superseded decision
gets a new ADR that says so and links back, rather than editing history).

| # | Title | Status |
|---|---|---|
| [0001](0001-clean-architecture-with-ports-and-adapters.md) | Clean Architecture with Ports and Adapters | Accepted |
| [0002](0002-asyncio-as-the-async-runtime.md) | `asyncio` as the Async Runtime | Accepted |
| [0003](0003-cryptography-pyca-as-the-crypto-library.md) | `cryptography` (pyca) as the Sole Cryptographic Library | Accepted |
| [0004](0004-binary-header-with-msgpack-payload.md) | Fixed Binary Header + MessagePack Payload | Accepted |
| [0005](0005-sqlite-for-metadata-storage.md) | SQLite for Metadata Storage | Accepted |
| [0006](0006-filesystem-watcher-port-and-watchdog-adapter.md) | Filesystem Watcher Port with a `watchdog` Adapter | Accepted |
| [0007](0007-chunking-strategy-as-a-pluggable-port.md) | Chunking Strategy as a Pluggable Port (Strategy Pattern) | Accepted |
| [0008](0008-synchronous-chunk-engine-core-with-async-boundary.md) | Synchronous Chunk-Engine Core with an Async Use-Case Boundary | Accepted |
| [0009](0009-content-addressable-delta-computation.md) | Content-Addressable Delta Computation, Reusing the Phase 2 Chunk Cache | Accepted |
| [0010](0010-persistent-manifest-storage-is-chunk-repository.md) | Persistent Manifest Storage Is Already `ChunkRepository` / `FileChunkRepository` | Accepted |
| [0011](0011-peer-discovery-with-mdns-and-in-memory-repo.md) | Peer Discovery with mDNS and In-Memory Peer Cache | Accepted |
| [0012](0012-conflict-resolution-with-version-vectors.md) | Conflict Resolution with Version Vectors | Accepted |
| [0013](0013-sqlite-for-metadata-persistence.md) | SQLite for Metadata Persistence | Accepted |
| [0014](0014-synchronization-orchestrator-state-machine.md) | Synchronization Orchestrator State Machine | Accepted |
| [0015](0015-production-runtime-and-configuration.md) | Production Runtime and Configuration | Accepted |
| [0016](0016-in-process-encrypted-transport.md) | Real Use-Case Wiring, an In-Process Encrypted Transport, and the Disclosed Socket-Transport Gap | Accepted |
| [0017](0017-tcp-transfer-transport.md) | A Real TCP Transport — and Why It Still Isn't Wired Into `main.py` | Accepted |

## Template for new ADRs

```markdown
# ADR NNNN: <Title>

**Status:** Proposed | Accepted | Superseded by ADR-XXXX
**Date:** <phase or date>

## Context
<What forces are at play; what problem needs a decision>

## Decision
<The decision, stated plainly>

## Consequences
<Positive and negative trade-offs accepted>

## Rejected: <alternative>
<Why it wasn't chosen>
```
