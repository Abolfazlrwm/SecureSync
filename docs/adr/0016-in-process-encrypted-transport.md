# ADR 0016: Real Use-Case Wiring, an In-Process Encrypted Transport, and the Disclosed Socket-Transport Gap

**Status:** Accepted
**Date:** Post-Phase-10 integration audit

## Context

An audit of the working tree (everything claimed complete through
Phase 10) found that several components built in isolation, each with
passing unit tests, were never actually wired together:

- `SyncOrchestrator` (Phase 9) received `discovery_use_case`,
  `download_use_case`, `upload_use_case`, and `conflict_use_case` in
  its constructor but never called any of them outside `__init__` —
  its background loop only slept, with a comment reading *"In a real
  implementation, this would react to events."*
- `main.py` (Phase 10) constructed `SyncOrchestrator` with a
  hand-rolled `MagicMock` class standing in for all four use cases,
  commented *"Mocks for demonstration in this phase,"* with four
  `# type: ignore[arg-type]` suppressing the resulting (correct)
  mypy errors, and read `orchestrator._stop_event` directly — a
  private attribute accessed from outside the class.
- The entire crypto layer (Phase 6 — `PycaKeyExchangeProvider`,
  `AesGcmCipher`, `ChaCha20Cipher`) was fully unit-tested but never
  referenced anywhere else in the codebase; chunks would have moved
  over any real transport unencrypted.
- `TransferTransport.request_chunks` (Phase 5) was declared as a
  plain coroutine (no `yield`) but called with `async for` directly
  in `transfer_chunks.py`, papered over with
  `# type: ignore[attr-defined]` — and no concrete implementation of
  `TransferTransport` existed anywhere, including in tests (the one
  test file for `transfer_chunks.py` used an ad hoc sync function
  returning an async generator, sidestepping the real contract
  entirely).
- `core/protocol.py`'s `Packet.encode()` never actually computed the
  CRC32 it claims to, commented *"In a real implementation, CRC would
  be calculated here."*

These are exactly the kind of "looks done, isn't" gaps this project's
audit process exists to catch, individually confirmed by direct
inspection and runtime testing (not assumed from docstrings) before
any of this ADR's decisions were made.

## Decision

**Fix what was actually broken, first.** `core/protocol.py`'s
`Packet.encode()` now computes a real CRC32 and the correct
`payload_length` from the actual serialized payload; a matching
`Packet.decode()` (which didn't exist before) rejects a payload whose
CRC32 or length doesn't match, raising the new `PayloadIntegrityError`
(previously: nothing checked this at all). `TransferTransport.request_chunks`'s
abstract method now includes an (unreachable, `# pragma: no cover`)
`yield` after its `raise NotImplementedError`, making it a real async
generator function per Python's own rules — every implementation can
now be iterated with a direct `async for`, and the
`# type: ignore[attr-defined]` in `transfer_chunks.py` was removed
because the type error it suppressed no longer exists. Verified at
runtime, not just by inspection: `inspect.isasyncgen()` on a concrete
implementation now returns `True`, and a full send→receive round trip
runs correctly without an extra `await`.

**Build the one missing concrete piece that connects everything:
`InProcessTransferTransport`** (`infrastructure/networking/in_process_transport.py`).
It implements `TransferTransport` for real: `send_chunk` frames a chunk
through `core/protocol.py` (real CRC-checked, msgpack-encoded bytes),
encrypts the framed bytes with an injected `AeadCipher` and key, and
delivers them to the recipient's inbox in a shared `InProcessNetwork`;
`request_chunks` reads its own inbox, decrypts, and reconstructs each
`Chunk`. This is not a toy: `UploadChunksUseCase`/`DownloadChunksUseCase`
(unmodified) were run against two `InProcessTransferTransport`
instances and correctly transferred multiple chunks end to end, with a
wrong decryption key confirmed to raise `cryptography.exceptions.InvalidTag`
rather than silently succeeding. It does not touch
`Chunk.__post_init__`'s `len(data) == metadata.size` invariant from
Phase 2 — encryption happens entirely in the wire-framing layer, never
by mutating a `Chunk`'s `data` field, so that invariant needed no
change.

**Wire `SyncOrchestrator` to real dependencies, honestly bounded by
what data actually exists to wire.** `start()`/`stop()` now call
`discovery_use_case.start()`/`.stop()` for real. The background loop
polls `DiscoverPeersUseCase.list_online_peers()` (new method, backed
by the real `PeerRepository`) every 5 seconds and reacts to newly
online peers via `handle_peer_discovered`, which now performs a real
read against `MetadataRepository.list_all_files()` to refresh
`stats.files_processed`. `download_use_case`/`upload_use_case` became
optional constructor parameters (`| None = None`): actually invoking
them per peer requires exchanging remote manifests over the network
first, and no such RPC exists in this codebase — inventing one now,
with fabricated inputs, would just move the "looks done, isn't"
problem rather than fix it. Where that call would go, `handle_peer_discovered`
now logs a specific, traceable `chunk_transfer_not_available` event
naming the real cause, replacing the previous vague *"In a real
scenario, this might trigger..."* comment.

**A public `wait_until_stopped()` replaces the private-attribute read.**
`main.py` no longer reaches into `orchestrator._stop_event`.

**`main.py` uses real adapters for everything that has one.** The
`MagicMock` class and all four `# type: ignore[arg-type]` are gone.
`discovery_use_case` is a real `DiscoverPeersUseCase` over a real
`MdnsDiscoveryService` and `InMemoryPeerRepository`; `conflict_use_case`
is a real `DetectConflictUseCase` over a real `InMemoryConflictRepository`.
`download_use_case`/`upload_use_case` are left unset, with a code
comment explaining exactly why (`InProcessTransferTransport` only
connects peers in one process; this is a single-instance entry point)
rather than silently omitted.

## Consequences

**Positive**

- Every one of the fixes above was runtime-verified in this session
  (not merely reasoned about): the protocol round trip, the
  tamper-detection paths, the full encrypted multi-chunk transfer
  through the unmodified application use cases, and the orchestrator's
  real discovery-start/stop calls and metadata-driven stats update.
- `SyncOrchestrator`'s state machine and stats now reflect activity
  that actually happened (a real peer-repository read, a real
  metadata-repository read) instead of being updated by code that
  never ran.
- The remaining gap (no socket-based `TransferTransport`, so no real
  cross-machine chunk transfer yet) is now a single, explicitly named,
  ADR-documented fact instead of a silently-passing mock — the next
  engineer (or session) has one clear, correctly-scoped task instead
  of an unknown number of hidden ones.

**Negative / trade-offs accepted**

- SecureSync still cannot transfer chunks between two different
  machines. `InProcessTransferTransport` proves the crypto+transfer
  wiring is correct, but a real socket/TLS transport — accepting
  connections, framing over a stream, handling reconnects — remains
  unbuilt. This was true before this ADR and remains true after it;
  what changed is that it's now the *only* remaining gap in the
  transfer path, clearly named, rather than one of several
  undisclosed ones.
- `SessionKeyProvider.derive_session_keys`'s send/receive key-swap
  ambiguity (flagged in its docstring during the earlier docstring
  audit) is still unresolved, because nothing in this codebase calls
  it yet — there is no live handshake to get the swap right or wrong
  in. Whichever code performs the real X25519 handshake in the future
  must resolve initiator/responder role assignment for these keys;
  this ADR does not invent that handshake speculatively.
- `InProcessTransferTransport.request_chunks` has no real
  request/response round trip — it only reads whatever the peer
  already pushed via `send_chunk`, filtering by requested hash and
  logging (not erroring on) anything unmatched. This is enough to
  validate the crypto+use-case wiring; a real pull-based protocol
  (peer A asks B for specific hashes; B looks them up and responds)
  is part of the same future socket-transport work, not added
  speculatively here.

## Rejected: fabricate remote data to force download/upload/conflict use cases to run

Would make `SyncOrchestrator`'s stats non-zero and its log lines look
busier, but the values would be meaningless — there is no real remote
manifest behind them. This is the same category of problem the audit
exists to catch; recreating it to make dashboards look complete would
defeat the point of doing this integration work honestly.

## Rejected: build a full TCP/TLS socket transport now

The correctly-scoped fix for "connect crypto to transfer" doesn't
require sockets — `InProcessTransferTransport` proves the encryption
and application-layer wiring are correct without them. A real network
transport is a substantial, separate piece of work (connection
lifecycle, backpressure, reconnect logic, and its own test
infrastructure this sandbox can't fully exercise given the missing
`zeroconf` dependency even for the already-existing `MdnsDiscoveryService`)
better scoped as its own deliberate phase than folded into this
integration pass.
