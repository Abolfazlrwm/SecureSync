# Roadmap

Each phase is completed, reviewed, and merged before the next one starts.
Status is updated at the end of every phase alongside `CHANGELOG.md`.

- [x] **Phase 0 — Architecture & Scaffolding**
      Clean Architecture layers, repository structure, dependency decisions,
      initial documentation set, README skeleton.
- [x] **Phase 0.5 — Repository & Documentation Polish**
      Full community health files, CI workflow, issue/PR templates, complete
      documentation set (networking, protocol, security/threat model,
      performance/benchmark plan, development, deployment, configuration,
      troubleshooting), ADRs 0001–0005, all Mermaid diagram types, visual
      assets. No application code — see `CHANGELOG.md` for the full list.
- [x] **Phase 1 — Filesystem Watcher**
      Monitor create/modify/delete/rename/move across multiple directories,
      recursively, with debouncing, async dispatch, and graceful shutdown
      (Observer pattern, `watchdog`-based adapter behind a domain port).
      111 tests, 98% coverage — see `CHANGELOG.md` for the full list.
- [x] **Phase 2 — Chunk Engine**
      Streaming, bounded-memory chunking (`ChunkingStrategy` port, Strategy
      pattern) with `FixedSizeChunkingStrategy` (default 4 MiB, configurable)
      and a SHA-256 hash engine (`hashlib` only). Content-defined chunking
      (rolling hash / Rabin fingerprint / FastCDC) is reserved behind the
      same port, not implemented yet — see ADR-0007. Synchronous core with
      an async use-case boundary via `asyncio.to_thread` — see ADR-0008.
      258 tests, 98% coverage — see `CHANGELOG.md` for the full list.
- [x] **Phase 3 — Delta Synchronization**
      Hash comparison against a recorded baseline (`DeltaCalculator`, a
      stateless domain service matching chunks by content hash, not
      position — see ADR-0009), reusing the Phase 2 `ChunkRepository`
      as the chunk cache. `ComputeDeltaUseCase` classifies each of a
      file's current chunks as needing transfer or reusable from the
      baseline. No new cache, no transfer wiring — sending the
      resulting `chunks_to_transfer` over the network is Phase 5's
      job. 21 new tests — see `CHANGELOG.md` for the full list.
- [x] **Phase 3.5 — Persistent Manifest Repository (retroactive)**
      Formal documentation of a capability already delivered, not new
      code: `ChunkRepository` (Phase 2 port) and its
      `FileChunkRepository` adapter already are this project's
      persistent manifest repository — one JSON document per file,
      atomic crash-safe writes, OS-safe hashed filenames, meaningful
      rejection of corrupted/incomplete manifests — reused unchanged
      in Phase 3 as the delta-sync chunk cache. An external brief
      proposed rebuilding this under a new name
      (`JsonManifestRepository` + four new use cases); audited against
      the actual code and existing tests and found to already satisfy
      every substantive requirement, so no new component was added —
      see ADR-0010. No code changed; this entry exists so the roadmap
      accurately reflects when persistent manifest storage was
      actually established (Phase 2) rather than leaving that
      capability undocumented as its own milestone.
- [x] **Phase 4 — Peer Discovery**
      mDNS discovery (`zeroconf`), in-memory peer repository (cache),
      `DiscoverPeersUseCase` for online/offline tracking.
- [x] **Phase 5 — Transfer Engine**
      Binary wire protocol (32-byte header, MessagePack payload),
      `TransferTransport` port, `UploadChunks`/`DownloadChunks` use cases.
- [x] **Phase 6 — End-to-End Encryption**
      X25519 key exchange, HKDF session key derivation, AES-256-GCM and
      ChaCha20-Poly1305 AEAD ciphers (`cryptography.io` adapters).
- [x] **Phase 7 — Conflict Resolution**
      Version vectors for causal tracking, conflict detection, and
      pluggable merge strategies (Last Writer Wins).
- [x] **Phase 8 — Metadata Database**
      SQLite-backed repository for persistent storage of files, chunks,
      and version history.
- [x] **Phase 9 — Synchronization Orchestrator**
      Central coordination of all components with a state machine and
      lifecycle management.
- [x] **Phase 10 — Production Runtime**
      YAML configuration system, application bootstrap, and graceful
      shutdown with signal handling.
- [x] **Phase 10.5 — Real Integration (post-hoc audit)**
      An audit of Phases 5, 6, 9, and 10 found real components built
      and individually unit-tested but never actually wired together:
      `SyncOrchestrator`'s injected use cases were never called outside
      `__init__`; `main.py` used a hand-rolled `MagicMock` for all four
      of them; the entire crypto layer (Phase 6) was never referenced
      by anything else; `TransferTransport.request_chunks` had a
      type-incorrect signature masked by a `# type: ignore`, with no
      concrete implementation anywhere; and `core/protocol.py`'s CRC32
      was never actually computed. All fixed and runtime-verified —
      see ADR-0016 for the full account, including the one gap that's
      still honestly open: no socket-based `TransferTransport` exists
      yet, so cross-machine transfer isn't possible. A new
      `InProcessTransferTransport` (real AEAD encryption, real
      `core/protocol.py` framing) proves the crypto+transfer wiring is
      correct for same-process peer pairs.

## Advanced features (introduced opportunistically, in the phase they fit)

Custom binary protocol · plugin system · event bus · job scheduler ·
parallel chunk upload · resume interrupted transfer · exponential backoff
retry · compression layer · rate limiter · peer authentication · device
fingerprinting · version history & rollback · metrics collection ·
benchmark suite · structured logging · config validation · threat model
documentation · ADRs · release notes · health checks · protocol
versioning · plugin API · performance/memory profiling · cross-platform
support.

## Out of scope for now

- Merkle tree chunk verification (reserved, see chunk engine notes)
- Content-defined chunking — rolling hash / Rabin fingerprint / FastCDC
  (reserved behind the `ChunkingStrategy` port, see ADR-0007)
- Multi-language client implementations
