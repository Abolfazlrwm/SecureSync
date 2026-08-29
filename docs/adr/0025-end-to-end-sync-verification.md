# ADR 0025: End-to-End Sync Verification

**Status:** Accepted
**Date:** Phase 20

## Context

Phases 0-19 built and unit-tested every layer of the sync pipeline in
isolation — chunking, delta computation, discovery, encryption,
conflict resolution, metadata storage, and the version-aware direction
logic from ADR-0024 — but no test had ever run two full, independently
bootstrapped instances of the actual application and confirmed a file
created on one device ends up correctly on the other. This phase
built that test and, as intended, it immediately surfaced real bugs
and gaps that unit tests — which necessarily construct their own
components in isolation — couldn't see.

## What the test found

### 1. `main.py` never actually wired the Phase 15-17 sync pipeline in

`SyncOrchestrator` was constructed without `sync_file_use_case`,
`sync_root`, or `chunking_strategy`. `_auto_push_known_files` silently
no-ops whenever `sync_file_use_case` is `None` — which it always was
in every real run of the application. `SyncFileUseCase`,
`SyncDirectionResolver`, `ChunkFileUseCase`, `CalculateChunkHashesUseCase`,
and `LocalFileReconstructor` were all built, unit-tested, and
documented (ADR-0022, ADR-0024) — and never once constructed by
`main.py`. Every phase since 15 had been adding real, tested code to a
pipeline the running application didn't use.

**Fixed:** `bootstrap()` now constructs and wires
`SyncFileUseCase` (with `SyncDirectionResolver`) and passes it, along
with `sync_root` and a `FixedSizeChunkingStrategy`, into
`SyncOrchestrator`. `TcpManifestExchangeTransport` is also now given
`metadata_lookup=metadata_repo` so its manifest responses include a
real version vector, which ADR-0024's direction resolver needs.

### 2. `TcpTransferTransport` looked up sessions under the wrong key

`send_chunk` and `request_chunks` both called
`self._session_keys.get(self._own_device_id)`. Every place a session
is ever stored (`X25519SessionCoordinator.ensure_session`, `main.py`'s
`_drain_inbound_handshakes`) keys it by the **peer's** device_id, never
by this device's own — so that lookup could only succeed by the
coincidence of a peer sharing this device's device_id, which never
happens. This shipped in the very first version of `tcp_transport.py`
and passed every existing unit test, because
`tests/unit/infrastructure/networking/test_tcp_transport.py`'s fixture
happened to populate a single shared `SessionKeyStore` under *both*
devices' own IDs, masking the mismatch. The real bug only surfaced
once two genuinely separate `SessionKeyStore` instances (one per real
process) were involved, which unit tests never do.

**Fixed:** both lookups now use `peer.device_id`, matching every other
transport in the codebase (`TcpManifestExchangeTransport` already did
this correctly). The test fixture was corrected to match production
semantics — each entry represents *my own* session for talking to a
specific peer, stored under *that peer's* ID — rather than being
restructured to hide the bug again.

### 3. `TcpTransferTransport.send_chunk` connected to the wrong port

`send_chunk` opened its connection to `peer.address.port` — the
peer's **handshake** port — instead of the peer's negotiated transfer
port recorded in the session (`PeerSession.transfer_port`, populated
from `result.peer_transfer_port` during the handshake). Sending a
push therefore connected to the peer's `X25519Handshake` server, which
correctly rejected the encrypted chunk envelope as an invalid
handshake message. `TcpManifestExchangeTransport` already used
`session.manifest_port` for the equivalent connection, which is what
exposed the inconsistency.

**Fixed:** `send_chunk` now connects to `own_session.transfer_port`,
matching the manifest exchange transport's existing pattern.

### 4. Known, disclosed gap: nothing autonomously drains a pushed chunk on the receiving side

With bugs 2 and 3 fixed, a pushed chunk really does arrive, correctly
encrypted, at the peer's real listening transfer socket. But nothing
in `SyncOrchestrator` or `main.py` actively drains an unsolicited
inbound push and reconstructs the file — `TcpTransferTransport`'s
server side only queues incoming envelopes into an internal inbox;
something has to call `request_chunks` (via `DownloadChunksUseCase`)
expecting specific hashes to consume it. `SyncFileUseCase.pull` never
hits this problem because it uses `ManifestExchangeTransport.request_chunks`
instead — a genuine request/response RPC over the manifest port,
already flagged as the reason `pull` exists separately from `push` in
ADR-0022. `push`, by contrast, has no autonomous receiver.

This is real, pre-existing incompleteness, not something this phase
introduced — it's the natural consequence of bug 1: since
`sync_file_use_case` was never wired at all, nobody had exercised the
push path against a genuinely separate second process before. It is
deliberately **not fixed in this phase** — building a correct
background "push receiver" (matching arriving chunks to the file and
offset they belong to, handling partial/out-of-order delivery) is
real, scoped design work, not a follow-on one-liner. It's tracked as
future work.

`tests/integration/test_end_to_end_sync.py` documents this precisely:
it verifies the full real push (two real processes, real identities,
real handshake, real encrypted chunk delivery to the correct socket)
completes correctly on the wire, then completes the receiving side
itself via the same real `DownloadChunksUseCase` a background receiver
would eventually use, so the test still proves the wire format and
crypto round-trip byte-for-byte across two independent processes.

## Consequences

- Real cross-device sync (the entire point of Phases 11-19) now
  actually runs when the daemon starts, for the first time.
- The project's two most-tested-in-isolation layers (transport,
  orchestration) had bugs that only a genuine two-process test could
  catch — this justifies keeping `test_end_to_end_sync.py` in the
  suite permanently rather than treating it as a one-off exercise.
- A "push receiver" component is the clear next piece of real,
  scoped work; it should not be bundled into an unrelated phase the
  way `sync_file_use_case`'s wiring gap sat unnoticed for four phases.
