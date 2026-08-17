# ADR 0021: A Real Manifest Exchange Protocol

**Status:** Accepted
**Date:** Post-Phase-13 follow-up

## Context

By the end of Phase 13, SecureSync could authenticate two peers,
negotiate encrypted session keys, and move chunk bytes between them —
but only if the caller already knew *which* chunks needed moving.
Nothing let one peer ask another "what do you have for this file?" —
the one piece of information `DeltaCalculator` (Phase 3) actually
needs to compute anything. Without it, no synchronization can happen
between two real machines regardless of how correct every other layer
is.

## Decision

**`ManifestExchangeTransport`** (`domain/manifest_exchange.py`) is a
new, minimal port: `request_manifest(peer, source_path) -> ChunkCollection | None`.
Placed deliberately alongside `TransferTransport` rather than folded
into it — moving chunk bytes and answering "what do you have" are
different request shapes (fire-and-forget push vs. request/response),
and Phase 11-13 already established that pattern split for a reason
(see ADR-0016's "Rejected: give `TcpTransferTransport` its own
internal handshake logic").

**`TcpManifestExchangeTransport`** is a real request/response
implementation, structurally similar to `X25519Handshake` (one
connection, write a request, read a response, close) rather than
`TcpTransferTransport`'s push-to-inbox model, because a manifest
lookup genuinely needs an answer on the same connection. It reuses
the *already-negotiated* `PeerSession` keys from the handshake — no
separate key exchange for this port — and serves manifests from the
same `ChunkRepository` `ComputeDeltaUseCase` already reads baselines
from (ADR-0010: that repository already is SecureSync's persistent
manifest store, so nothing new was introduced to serve from).

**The manifest (de)serialization functions were made public**
(`collection_to_dict`/`collection_from_dict`, previously
`_collection_to_dict`/`_collection_from_dict` in
`file_chunk_repository.py`) instead of duplicated. A ~40-line format
used identically for disk persistence and network transport is one
function pair, not two independently-maintained copies.

**A third negotiated port.** `HandshakeResult`/`PeerSession` now carry
`peer_manifest_port` alongside `peer_transfer_port`, exchanged the
same way (as part of the signed handshake payload, not guessed from
an offset — see ADR-0020's reasoning, which applies identically here).
Verified in this session: a full chain — handshake exchanges the real
manifest port, `TcpManifestExchangeTransport` connects to exactly that
port, and a request for a file the peer actually has returns its real
`ChunkCollection` (chunk hash confirmed matching), while a request for
a file the peer doesn't have correctly returns `None` rather than
erroring.

**`main.py` starts and stops the manifest exchange transport**
alongside the chunk transfer transport, verified by actually running
`bootstrap()` through `orchestrator.start()`. It is *not* yet called by
`SyncOrchestrator`'s automatic discovery loop — see Consequences.

## Consequences

**Positive**

- The last missing piece for genuine cross-machine synchronization —
  discovering what a peer has — is now real and verified, not just
  planned.
- Reusing `PeerSession` keys means no additional handshake round trip
  or key-management surface for this port; authentication and
  encryption are inherited from the same trust established in
  ADR-0018/0019.
- Reusing `ChunkRepository`/its serialization functions instead of a
  parallel manifest store keeps this consistent with ADR-0010's
  "no second manifest-storage component" decision — the same
  reasoning applies to a network-facing store as it did to a
  Phase-4-brief-proposed local one.

**Negative / trade-offs accepted**

- **`SyncOrchestrator` still doesn't call this automatically.**
  `handle_peer_discovered` establishes a session but doesn't yet
  request any peer's manifests, compute a delta against them, or
  transfer anything as a result — the mechanism to *do* that now
  exists and is verified in isolation, but the orchestration loop
  that would iterate local files, request each peer's manifest for
  each, and act on the resulting `DeltaPlan` is genuinely separate
  work, not addressed here. This is the same category of disclosure
  ADR-0016/0017 made about the transport layer, now made about the
  orchestration layer instead.
- No manifest caching: every `request_manifest` call is a fresh round
  trip, even if called repeatedly for the same file in quick
  succession. Acceptable for now — nothing calls it more than once
  per file yet, since nothing calls it automatically at all.
- A peer can request a manifest for *any* path it names, with no
  access-control check beyond "the requester completed a handshake."
  There's no concept yet of which files a peer is allowed to see
  manifests for versus which are private to the local device — every
  synced file is implicitly shared with every authenticated peer.

## Rejected: fold manifest requests into `TcpTransferTransport`

Would reduce the number of ports and classes, but conflates two
different request shapes (push vs. request/response) into one
transport's responsibility, the same trade-off already rejected for
the handshake in ADR-0016.

## Rejected: duplicate the serialization functions instead of exporting them

Would avoid touching `file_chunk_repository.py`, but keeping two
copies of the same ~40-line format is a DRY violation with a real
cost: a future field added to `ChunkMetadata` would need updating in
two places, and it's easy to update one and forget the other.
