# ADR 0011: Peer Discovery with mDNS and In-Memory Repository

**Status:** Accepted
**Date:** 2026-07-30

## Context

Discovery needs a network-level mechanism (UDP broadcast, mDNS), a peer cache, and identity management. The system must find other SecureSync instances on the local network without central coordination.

## Decision

1.  **Domain Abstractions**: Introduced `Peer`, `PeerIdentity`, `PeerAddress`, and `PeerCapabilities` as core domain entities in `domain/networking.py`.
2.  **Discovery Port**: Defined `DiscoveryService` as the port for network-level discovery and `PeerDiscoveryObserver` for reacting to discovery events.
3.  **Repository Port**: Defined `PeerRepository` for persisting known peers.
4.  **mDNS Implementation**: Implemented `MdnsDiscoveryService` using the `zeroconf` library. It handles service advertisement (announcing this device) and browsing (finding others).
5.  **Temporary Persistence**: Implemented `InMemoryPeerRepository` as a thread-safe in-memory store. This satisfies the "Peer Cache" requirement for peer discovery, with durable peer persistence deferred to the SQLite metadata store when a concrete need for it arrives.
6.  **Use Case Orchestration**: Created `DiscoverPeersUseCase` to bridge the discovery service and the repository, ensuring discovered peers are marked `ONLINE` and lost peers are marked `OFFLINE`.

## Consequences

### Positive
- **Decoupling**: The discovery logic is completely isolated from the peer management and sync logic.
- **Testability**: The use case can be tested with mocks, and the repository has a dedicated in-memory implementation.
- **Standards-based**: Using mDNS (`zeroconf`) ensures compatibility with standard network discovery tools.

### Negative / Trade-offs
- **In-memory only**: Peer discovery state is lost on restart until the SQLite metadata store lands. This is acceptable for the current development phase.
- **UDP Broadcast**: While requested, mDNS was prioritized as the primary mechanism due to its better handling of service metadata and cross-platform reliability. UDP broadcast can be added as a second adapter behind the same port if needed.
