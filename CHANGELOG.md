# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added — Phase 15: File Synchronization Use Case
- `application/use_cases/sync_file.py` (new): `SyncFileUseCase` with
  explicit `push`/`pull` methods (deliberately not one automatic
  bidirectional method — see below). Composes manifest exchange,
  `DeltaCalculator`, upload, and chunk pull into the first real
  "synchronize this file" operation.
- Three real bugs found and fixed while verifying this against two
  real peer processes (not found by inspection — each reproduced with
  an actual two-device test scenario):
  - Syncing a file that doesn't exist locally yet (the normal "first
    pull" case) crashed with `ChunkSourceNotFoundError`. Fixed:
    treated as an empty local manifest, not an error.
  - `ManifestExchangeTransport` originally identified files by
    absolute path — invisible across two peers whose sync
    directories live at different absolute locations. Fixed: every
    cross-peer file reference (`request_manifest`, the new
    `request_chunks`, `SyncFileUseCase`'s own parameters) now uses a
    path relative to each side's own sync root.
    `TcpManifestExchangeTransport` gained a `sync_root` constructor
    parameter to resolve a peer's relative request back to this
    device's own absolute path.
  - An automatic-bidirectional first version of this use case
    silently overwrote a device's own fresh edit with a peer's stale
    copy of the same chunk — verified with an actual round-trip test
    that ended in mismatched file contents. Root cause: without a
    timestamp or version signal, a pure content-hash diff can't tell
    "new content the peer needs" apart from "stale content the peer
    has already moved past." Fixed by making `push` and `pull`
    separate, explicit-direction methods instead of attempting
    automatic reconciliation — removing the ambiguity rather than
    patching around it (a heuristic guard was tried first and found
    insufficient — the same ambiguity corrupted the upload decision
    too, not just download).
- `domain/manifest_exchange.py`, `infrastructure/networking/tcp_manifest_exchange.py`:
  added a genuine `request_chunks(peer, relative_path, chunk_hashes)`
  pull — the requester actively asks, the responder reads the exact
  requested byte ranges from its own file and answers on the same
  connection. Needed because `TransferTransport.request_chunks`'s
  disclosed "no real request/response round trip" limitation
  (ADR-0017/0018) turned out to hang forever the first time a real
  caller (this use case) actually needed a pull.
- `domain/reconstruction.py`, `infrastructure/chunking/local_file_reconstructor.py`
  (new): `FileReconstructor` port + `LocalFileReconstructor` —
  writes a downloaded chunk's bytes at its correct offset within the
  file being reconstructed. Deliberately not Phase 2's `ChunkWriter`,
  which writes a chunk as its own standalone file. Verified:
  out-of-order chunk writes reassemble correctly; overwriting one
  chunk doesn't disturb others already written.
- `infrastructure/chunking/file_chunk_repository.py`: no changes
  needed beyond Phase 14's public `collection_to_dict`/`collection_from_dict`
  — reused again here for the chunk-response payload shape.
- Verified end to end across a full scenario: fresh push, fresh pull,
  an incremental edit pushed and pulled (only the changed chunk
  transferred each way, confirmed by count), and a final no-op push
  (zero chunks) — file contents matched byte-for-byte throughout.
- 10 new tests: `test_sync_file.py` (6, using new `FakeTransferTransport`
  and extended `FakeManifestExchangeTransport` doubles),
  `test_local_file_reconstructor.py` (4). `test_tcp_manifest_exchange.py`
  extended with 2 `request_chunks` tests (7 total).
- `docs/adr/0022-file-synchronization-use-case.md`: full account of
  all three bugs, why automatic bidirectional sync was rejected in
  favor of explicit push/pull, and what's still left to
  `SyncOrchestrator`'s automatic loop (deciding which direction is
  correct for a given file — real conflict detection, not addressed
  here).
- `ROADMAP.md`: added a **Phase 15** entry.

### Added — Phase 14: Manifest Exchange Protocol
- `domain/manifest_exchange.py` (new): `ManifestExchangeTransport`
  port — `request_manifest(peer, source_path) -> ChunkCollection | None`.
- `infrastructure/networking/tcp_manifest_exchange.py` (new):
  `TcpManifestExchangeTransport` — a real request/response
  implementation over TCP (one connection: write a request, read a
  response, close — structurally like `X25519Handshake`, not
  `TcpTransferTransport`'s push-to-inbox model, since a manifest
  lookup needs an answer on the same connection). Reuses the
  already-negotiated `PeerSession` keys from the handshake and serves
  manifests from the same `ChunkRepository`
  `ComputeDeltaUseCase` already reads baselines from.
- `infrastructure/chunking/file_chunk_repository.py`: `_collection_to_dict`/
  `_collection_from_dict` made public (`collection_to_dict`/
  `collection_from_dict`) so the network transport reuses the same
  serialization logic as disk persistence instead of duplicating it.
- `infrastructure/networking/x25519_handshake.py`,
  `infrastructure/networking/session_key_store.py`: `HandshakeResult`/
  `PeerSession` gained `peer_manifest_port`/`manifest_port`, exchanged
  as part of the signed handshake payload the same way
  `transfer_port` already was (ADR-0020's reasoning applied again).
- `domain/config.py`: added `NetworkConfig.manifest_port` (default `8083`).
- `main.py`: starts and stops `TcpManifestExchangeTransport` alongside
  the chunk-transfer transport. Verified by running `bootstrap()`
  through `orchestrator.start()` successfully.
- Verified end to end: a handshake between two instances correctly
  exchanges the real manifest port; a manifest request for a file the
  peer has returns its real `ChunkCollection` (chunk hash confirmed
  matching); a request for a file it doesn't have returns `None`.
- 3 new tests in `test_tcp_manifest_exchange.py`, all running against
  real sockets. `tests/doubles.py`: added `FakeManifestExchangeTransport`
  per `CONTRIBUTING.md`'s every-new-port-needs-a-fake rule.
- `docs/adr/0021-manifest-exchange-protocol.md`: full rationale, and
  the explicitly disclosed remaining gap — `SyncOrchestrator`'s
  automatic loop doesn't call this yet, so discovering a peer
  establishes a session but doesn't request manifests, compute deltas,
  or transfer anything as a result.
- `ROADMAP.md`: added a **Phase 14** entry naming that orchestration
  loop as the next explicit step.

### Added — Phase 13: Peer Authentication and Full main.py Wiring
- `domain/identity.py` (new): `IdentityKeyPair`, `IdentityProvider`
  (load/create a persistent identity, sign, verify), and
  `TrustedPeerRepository` (pin/check a peer's long-term public key).
  `domain/identity_exceptions.py` (new): `IdentityError`,
  `InvalidHandshakeSignatureError`, `PeerIdentityMismatchError`.
- `infrastructure/crypto/ed25519_identity_provider.py` (new):
  `Ed25519IdentityProvider` — persists a device's Ed25519 identity as
  two files (`identity.private`, restricted to `0o600` where
  supported; `identity.public`), generated once, reloaded thereafter.
  Verified: persistence across instances, valid/tampered/wrong-key
  signature verification.
- `infrastructure/networking/file_trusted_peer_repository.py` (new):
  `FileTrustedPeerRepository` — atomically-written JSON trust store.
  Verified: unknown-peer lookup, pin-and-retrieve, persistence across
  instances, independent multi-peer entries.
- `infrastructure/networking/x25519_handshake.py`: every handshake
  message is now signed with the sender's persistent Ed25519 identity
  and verified against `TrustedPeerRepository` (trust-on-first-use).
  Verified end to end: a genuine repeat handshake with the same
  identity succeeds; an impostor presenting a *different* identity for
  an already-trusted `device_id` is rejected (`HandshakeServer`
  publishes no result for it). See ADR-0019.
- `infrastructure/networking/session_key_store.py` (new):
  `SessionKeyStore` (`device_id -> PeerSession`) and `PeerSession`
  (`send_key`, `receive_key`, `transfer_port`) — replaces
  `TcpTransferTransport`'s single fixed key pair, so a device can hold
  independently-keyed sessions with multiple peers simultaneously.
- `infrastructure/networking/x25519_handshake.py`: `X25519Handshake`
  now exchanges each side's chunk-transfer port as part of the signed
  handshake payload (`HandshakeResult.peer_transfer_port`) rather than
  guessing it from a port-offset convention. Verified: a handshake
  between instances on non-adjacent ports correctly taught each side
  the other's real transfer port, and `TcpTransferTransport.send_chunk`
  connected to that negotiated port.
- `infrastructure/networking/tcp_transport.py`: refactored from fixed
  `send_key`/`receive_key` constructor parameters to a `SessionKeyStore`
  looked up per call by `peer.device_id` — no wire-format change needed,
  since `send_chunk`/`request_chunks` already took `peer` as a parameter.
- `domain/handshake.py` (new): `SessionCoordinator` port, so
  `SyncOrchestrator` (application layer) can depend on "ensure a
  session exists for this peer" without depending on
  `X25519Handshake` (infrastructure) directly.
  `infrastructure/networking/x25519_session_coordinator.py` (new):
  `X25519SessionCoordinator`, the concrete adapter.
- `application/orchestration.py`: `SyncOrchestrator` gained an
  optional `session_coordinator` parameter; `handle_peer_discovered`
  calls `ensure_session` for newly discovered peers, catching and
  logging any failure (counted in `stats.errors_encountered`) so one
  peer's failed handshake doesn't stop discovery of others. Verified:
  3 new tests covering the call, graceful failure, and the no-coordinator
  default.
- `main.py`: fully wired — real `Ed25519IdentityProvider`,
  `FileTrustedPeerRepository`, `X25519Handshake` (both initiator via
  `X25519SessionCoordinator` and responder via `HandshakeServer`, with
  a new `_drain_inbound_handshakes` background task feeding inbound
  results into the same `SessionKeyStore`), and `TcpTransferTransport`.
  `download_use_case`/`upload_use_case` are no longer `None`. Verified
  by actually running `bootstrap()` in this session (with `zeroconf`/
  `aiosqlite` stood in for, since neither is installed in this
  sandbox) through `orchestrator.start()` binding real handshake and
  transfer ports successfully.
- `domain/config.py`: added `NetworkConfig.transfer_port` (default
  `8082`); `config.network.port` (already advertised via mDNS) is
  reused as the handshake port rather than adding a third port field.
- `tests/doubles.py`: added `FakeIdentityProvider` and
  `FakeTrustedPeerRepository` for the new `domain/identity.py` ports,
  per `CONTRIBUTING.md`'s every-new-port-needs-a-fake rule.
- `docs/adr/0019-peer-authentication-and-trust-on-first-use.md` and
  `docs/adr/0020-multi-peer-session-keys-and-main-py-wiring.md`:
  full account of both decisions, what was verified, and the
  trade-offs accepted (TOFU's first-contact weakness, no key-rotation
  recovery path, `InProcessTransferTransport` intentionally not
  refactored to the same session-key model since it's a test-only
  component).
- `ROADMAP.md`: added a **Phase 13** entry; Phase 12's two originally
  disclosed follow-ups (peer authentication, `main.py` wiring) are now
  both marked resolved there.

### Added — Phase 12: Key Exchange Handshake
- `infrastructure/networking/x25519_handshake.py` (new):
  `X25519Handshake` (initiator/responder halves of a real X25519
  exchange over TCP) and `HandshakeServer` (accepts inbound
  handshakes, publishes results to a queue). Resolves the exact
  ambiguity `PycaSessionKeyProvider.derive_session_keys`'s docstring
  flagged: initiator and responder deterministically get
  complementary `(send_key, receive_key)` pairs by role convention
  (initiator: `(key_1, key_2)`; responder: swapped `(key_2, key_1)`).
  Verified over a real socket: `initiator.send_key == responder.receive_key`
  and `initiator.receive_key == responder.send_key` both hold, the two
  keys are confirmed distinct, and repeated handshakes produce
  different keys every time (fresh ephemeral keypair + salt each
  time).
- `infrastructure/networking/in_process_transport.py` and
  `infrastructure/networking/tcp_transport.py`: refactored from a
  single shared `key: bytes` to separate `send_key`/`receive_key`
  parameters, matching what a real handshake actually produces.
  Breaking change to code added earlier in this same integration
  effort (ADR-0016/0017), not to any previously-stabilized phase.
- Full chain verified end to end, no hardcoded key anywhere: a real
  `X25519Handshake` negotiates keys over a real socket, those exact
  keys construct two `TcpTransferTransport` instances, and a chunk
  uploads and downloads correctly through the unmodified
  `UploadChunksUseCase`/`DownloadChunksUseCase`.
- 4 new tests in `test_x25519_handshake.py`; `test_in_process_transport.py`
  and `test_tcp_transport.py` updated for the new constructor
  signature (12 tests total across the three files, all passing).
- `docs/adr/0018-key-exchange-handshake.md`: the role-swap resolution,
  what was verified, and the two things this handshake still doesn't
  do — peer authentication, and wiring into `main.py` — disclosed
  explicitly rather than silently deferred.
- `ROADMAP.md`: added a **Phase 12** entry, checked, with both
  disclosed follow-ups named.

### Added — Phase 11: Real Network Transport (partial — not yet wired into main.py)
- `infrastructure/networking/tcp_transport.py` (new): `TcpTransferTransport` —
  a real `TransferTransport` implementation over `asyncio` TCP
  sockets. `start()`/`stop()` open and close a real listening socket;
  `send_chunk` opens a short-lived outbound connection per chunk;
  `request_chunks` reads from an inbox populated by the listening
  server. Each connection carries one length-prefixed (TCP has no
  message boundaries of its own), AEAD-encrypted envelope using the
  same `core/protocol.py` framing as `InProcessTransferTransport`.
  Verified over real localhost sockets, not just reasoned about:
  bidirectional multi-chunk transfer through the unmodified
  `UploadChunksUseCase`/`DownloadChunksUseCase`, and a wrong key
  correctly raising `cryptography.exceptions.InvalidTag`.
- 4 new tests in `tests/unit/infrastructure/networking/test_tcp_transport.py`,
  all running against real sockets on real (test-local) ports.
- `docs/adr/0017-tcp-transfer-transport.md`: why no TLS layer was
  added (message-level AEAD already provides confidentiality and
  integrity), and — just as importantly — why this still isn't wired
  into `main.py`: no code anywhere establishes the per-session key it
  needs. `PacketType.HELLO`/`KEY_EXCHANGE`/`AUTH` are declared and
  `PycaKeyExchangeProvider` exists, but no handshake calls them yet.
  Hardcoding a shared key into `main.py` to make the wiring "complete"
  was considered and rejected — see the ADR's "Rejected" section.
- `ROADMAP.md`: added a **Phase 11** entry, left unchecked, naming
  the handshake as the specific remaining prerequisite.

### Fixed — Phase 10.5: Real Integration (post-hoc audit)
- `core/protocol.py`: `Packet.encode()` never actually computed a
  CRC32 (comment: *"In a real implementation, CRC would be calculated
  here"*) — it now computes a real CRC32 and the correct
  `payload_length` from the actual serialized payload. Added
  `Packet.decode()` (didn't exist before), which raises the new
  `PayloadIntegrityError` on a CRC mismatch or truncated payload, and
  `InvalidHeaderError` (replacing generic `ValueError`) for a
  malformed header. Verified: encode→decode round-trips correctly; a
  single flipped payload byte is correctly rejected.
- `domain/transfer.py`: `TransferTransport.request_chunks` was
  declared as a plain coroutine (no `yield`) but called directly with
  `async for` in `transfer_chunks.py`, masked by
  `# type: ignore[attr-defined]`. The abstract method now includes an
  unreachable `yield` after `raise NotImplementedError`, making it a
  real async generator function per Python's rules; the
  `# type: ignore` was removed. Verified: `inspect.isasyncgen()` on a
  concrete implementation now returns `True`.
- `infrastructure/networking/in_process_transport.py` (new):
  `InProcessNetwork` + `InProcessTransferTransport` — a real,
  encrypted, tested `TransferTransport` implementation. `send_chunk`
  frames a chunk through `core/protocol.py` (real CRC-checked
  msgpack), encrypts with an injected `AeadCipher` + key, and delivers
  it to the recipient's inbox; `request_chunks` decrypts and
  reconstructs matching chunks from its own inbox. Verified against
  the real, unmodified `UploadChunksUseCase`/`DownloadChunksUseCase`:
  multiple chunks transferred correctly end to end; a wrong key
  correctly raises `cryptography.exceptions.InvalidTag` rather than
  silently succeeding. This is what actually connects the Phase 6
  crypto layer to chunk transfer — previously, nothing did.
- `application/orchestration.py`: `SyncOrchestrator`'s constructor
  never called any of its four injected use cases outside `__init__`;
  the sync loop only slept (comment: *"In a real implementation, this
  would react to events"*). `start()`/`stop()` now call
  `discovery_use_case.start()`/`.stop()` for real. The loop polls the
  new `DiscoverPeersUseCase.list_online_peers()` every 5 seconds and
  reacts via `handle_peer_discovered`, which now reads
  `MetadataRepository.list_all_files()` for real to refresh
  `stats.files_processed`. `download_use_case`/`upload_use_case`
  became optional (`| None`): actually calling them per peer needs a
  remote-manifest exchange this codebase doesn't have yet — see
  ADR-0016 for why that gap is disclosed rather than papered over
  with fabricated data. Also fixed: `stop()` could block for up to 5
  seconds waiting out an in-progress poll interval; it now returns as
  soon as requested (`asyncio.wait_for` on the stop event instead of a
  plain `asyncio.sleep`). Verified: 7 tests, including one asserting
  `stop()` completes in under 1 second.
- `main.py`: removed the hand-rolled `MagicMock` class and all four
  `# type: ignore[arg-type]` comments (comment: *"Mocks for
  demonstration in this phase"*). Now wires real adapters —
  `MdnsDiscoveryService` + `InMemoryPeerRepository` for discovery,
  `InMemoryConflictRepository` for conflict detection — everywhere a
  real one exists. `download_use_case`/`upload_use_case` are left
  unset with an explanatory comment (no socket-based transport exists
  yet; `InProcessTransferTransport` only connects peers in one
  process). Also fixed: `main.py` read `orchestrator._stop_event`
  directly (a private attribute); it now calls the new public
  `SyncOrchestrator.wait_until_stopped()`.
- `application/use_cases/discover_peers.py`: added
  `list_online_peers()`, needed by the orchestrator's polling loop
  above.
- `docs/adr/0016-in-process-encrypted-transport.md`: full account of
  every gap found, every fix made, and the one gap still honestly
  open (no real socket transport, so no cross-machine transfer yet).
- `ROADMAP.md`: added a **Phase 10.5** entry recording this audit,
  without renumbering any later phase.
- 12 new/updated tests: `test_protocol.py` (CRC round-trip, tamper
  and truncation rejection, domain-specific exceptions),
  `test_in_process_transport.py` (new — encrypted send/receive,
  wrong-key rejection, real use-case round-trip),
  `test_orchestration.py` (rewritten — real discovery start/stop,
  real metadata reads, prompt `stop()`), `test_discover_peers.py`
  (added `list_online_peers` coverage).

### Fixed — Phase 4-10 code-quality audit
- `infrastructure/crypto/pyca_crypto.py`: added Google-style
  docstrings to all 7 previously-undocumented public methods across
  `PycaKeyExchangeProvider`, `PycaSessionKeyProvider`, `AesGcmCipher`,
  and `ChaCha20Cipher` — including a documented warning on
  `derive_session_keys` about the send/receive key-swap ambiguity a
  future caller must resolve.
- `application/orchestration.py`: added docstrings to the `state` and
  `stats` properties.
- `domain/conflict_exceptions.py` (new): `ConflictError`,
  `ConflictNotFoundError`. `application/use_cases/conflict_resolution.py`
  now raises `ConflictNotFoundError` instead of a generic `ValueError`
  for an unknown `conflict_id`, matching the domain-specific-exception
  pattern used everywhere else in this codebase. Added a regression
  test.

### Added — Phase 10: Production Runtime
- `domain/config.py`: Defined `Configuration`, `StorageConfig`, `NetworkConfig`, and `RuntimeProfile` entities.
- `infrastructure/config/yaml_config_loader.py`: Implemented YAML configuration loading with `PyYAML`.
- `main.py`: Created the application bootstrap process, dependency injection wiring, and signal handling for graceful shutdown.
- `docs/adr/0015-production-runtime-and-configuration.md`: Documented the runtime and configuration architecture.
- Unit tests for configuration loading and validation.

### Added — Phase 9: Synchronization Orchestrator
- `application/orchestration.py`: Implemented `SyncOrchestrator` to coordinate discovery, transfer, metadata, and conflict resolution.
- `SyncState` machine and `SyncStats` for monitoring synchronization health and progress.
- `docs/adr/0014-synchronization-orchestrator-state-machine.md`: Documented the orchestration and state management design.
- Unit tests for the orchestrator lifecycle and event handling.

### Added — Phase 8: Metadata Database
- `domain/metadata.py`: Defined the `MetadataRepository` port and `FileMetadata` entity.
- `infrastructure/metadata/sqlite_metadata_repository.py`: Implemented a production-grade SQLite backend using `aiosqlite`.
- Relational schema for files and chunks with foreign key integrity and transactional support.
- `docs/adr/0013-sqlite-for-metadata-persistence.md`: Documented the database architecture and schema decisions.
- Unit tests for SQLite persistence, including chunk mapping and file metadata retrieval.

### Added — Phase 7: Conflict Resolution
- `domain/conflict.py`: Introduced `VersionVector` for causal tracking, `ConflictMetadata`, and `ConflictRepository` port.
- `application/use_cases/conflict_resolution.py`: Implemented `DetectConflictUseCase` and `ResolveConflictUseCase` with pluggable `MergeStrategy`.
- `LastWriterWinsStrategy` for automatic conflict resolution.
- `docs/adr/0012-conflict-resolution-with-version-vectors.md`: Documented the version vector and conflict detection logic.
- Unit tests for version vector arithmetic (increment, merge, comparison) and conflict detection/resolution use cases.

### Added — Phase 6: End-to-End Encryption
- `domain/crypto.py`: Defined `KeyExchangeProvider`, `SessionKeyProvider`, and `AeadCipher` ports.
- `infrastructure/crypto/pyca_crypto.py`: Implemented `cryptography.io` adapters for X25519, HKDF, AES-256-GCM, and ChaCha20-Poly1305.
- `docs/adr/0011-peer-discovery-with-mdns-and-in-memory-repo.md`: Combined ADR for networking and crypto decisions.
- Full unit tests for key exchange, session key derivation, and both AEAD ciphers.

### Added — Phase 5: Transfer Engine
- `core/protocol.py`: Implemented the binary wire protocol with a 32-byte header and MessagePack payload.
- `domain/transfer.py`: Defined `TransferTransport` and `TransferSession` ports.
- `application/use_cases/transfer_chunks.py`: Created `UploadChunksUseCase` and `DownloadChunksUseCase` for orchestrating data transfer.
- Unit tests for protocol serialization and transfer use cases.

### Added — Phase 4: Peer Discovery
- `domain/networking.py`: Introduced `Peer`, `PeerIdentity`, `PeerAddress`, and `PeerCapabilities` entities, plus `DiscoveryService` and `PeerRepository` ports.
- `infrastructure/networking/mdns_discovery.py`: Implemented mDNS discovery using the `zeroconf` library.
- `infrastructure/networking/in_memory_peer_repository.py`: Created a thread-safe in-memory peer cache.
- `application/use_cases/discover_peers.py`: Orchestrates discovery and peer status tracking.
- Unit tests for discovery, repository, and peer tracking.

### Documented — Phase 3.5: Persistent Manifest Repository (retroactive, no code change)
- Documented that `ChunkRepository`/`FileChunkRepository` already provided persistent manifest storage.
- Added `docs/adr/0010-persistent-manifest-storage-is-chunk-repository.md`.

### Added — Phase 3: Delta Synchronization
- `domain/delta.py`: `DeltaCalculator` for content-hash comparison.
- `application/use_cases/compute_delta.py`: `ComputeDeltaUseCase` for identifying chunks to transfer.

### Added — Phase 2: Chunk Engine
- Streaming, bounded-memory file chunking and SHA-256 hashing.

### Added — Phase 1: Filesystem Watcher
- Real-time filesystem monitoring using `watchdog`.
