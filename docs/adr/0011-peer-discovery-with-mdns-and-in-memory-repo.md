# ADR 0011: Peer Discovery with mDNS and In-Memory Repository

**Status:** Accepted
**Date:** 2026-07-30

## Context

Phase 4 requires implementing Peer Discovery, including UDP broadcast, mDNS, peer cache, and identity management. The system needs to discover other SecureSync instances on the local network without central coordination.

## Decision

1.  **Domain Abstractions**: Introduced `Peer`, `PeerIdentity`, `PeerAddress`, and `PeerCapabilities` as core domain entities in `domain/networking.py`.
2.  **Discovery Port**: Defined `DiscoveryService` as the port for network-level discovery and `PeerDiscoveryObserver` for reacting to discovery events.
3.  **Repository Port**: Defined `PeerRepository` for persisting known peers.
4.  **mDNS Implementation**: Implemented `MdnsDiscoveryService` using the `zeroconf` library. It handles service advertisement (announcing this device) and browsing (finding others).
5.  **Temporary Persistence**: Implemented `InMemoryPeerRepository` as a thread-safe in-memory store. This satisfies the "Peer Cache" requirement for Phase 4, with a permanent SQLite implementation deferred to Phase 8 per the existing roadmap.
6.  **Use Case Orchestration**: Created `DiscoverPeersUseCase` to bridge the discovery service and the repository, ensuring discovered peers are marked `ONLINE` and lost peers are marked `OFFLINE`.

## Consequences

### Positive
- **Decoupling**: The discovery logic is completely isolated from the peer management and sync logic.
- **Testability**: The use case can be tested with mocks, and the repository has a dedicated in-memory implementation.
- **Standards-based**: Using mDNS (`zeroconf`) ensures compatibility with standard network discovery tools.

### Negative / Trade-offs
- **In-memory only**: Peer discovery state is lost on restart until Phase 8 lands. This is acceptable for the current development phase.
- **UDP Broadcast**: While requested, mDNS was prioritized as the primary mechanism due to its better handling of service metadata and cross-platform reliability. UDP broadcast can be added as a second adapter behind the same port if needed.
