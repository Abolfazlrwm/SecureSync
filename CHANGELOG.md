# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
