# ADR 0001: Clean Architecture with Ports and Adapters

**Status:** Accepted
**Date:** Phase 0

## Context

SecureSync's core logic (conflict resolution rules, chunk diffing, version
tracking) needs to be verifiable through fast, deterministic unit tests —
without a real filesystem, real sockets, or a real SQLite database in the
loop. At the same time, several infrastructure concerns (transport
protocol, cipher choice, discovery mechanism) are explicitly expected to
change or gain alternatives over the project's life (see the master
feature list: TCP now, cipher choice between AES-GCM/ChaCha20-Poly1305,
UDP broadcast + mDNS).

Two alternatives were considered:

1. A simpler layered architecture (`cli/`, `core/`, `utils/`) without an
   explicit ports/adapters boundary.
2. A microservice split (separate processes for watcher, transfer engine,
   etc.) communicating over local IPC.

## Decision

Adopt Clean Architecture (Hexagonal / Ports & Adapters): `domain/` defines
interfaces (ports); `infrastructure/` provides concrete implementations
(adapters); `application/` orchestrates use cases against the ports, never
against concrete infrastructure classes directly; `presentation/` depends
only on `application/`.

## Consequences

**Positive**
- Domain and application logic is unit-testable with in-memory fakes —
  no real I/O needed for the majority of the test suite.
- Swapping an adapter (e.g. adding a QUIC transport alongside TCP) requires
  no change to application or domain code.
- The dependency rule (`domain/` has zero outgoing imports to other
  packages) is a single, simple, reviewable invariant.

**Negative / trade-offs accepted**
- More files and more indirection than a flat script-style layout —
  reasonable for a project explicitly built to production/portfolio
  standard, but would be overkill for a quick prototype.
- Contributors need to understand the ports/adapters pattern before their
  first non-trivial PR — mitigated by `docs/architecture.md` and this ADR.

## Rejected: microservice split

Rejected because SecureSync ships as a single binary/process per device;
splitting internal modules into separate OS processes would add IPC
complexity and deployment overhead without a corresponding scalability or
isolation benefit for a single-node sync agent.
