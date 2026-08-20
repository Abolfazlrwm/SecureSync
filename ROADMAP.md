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
- [ ] **Phase 11 — Real Network Transport**
      `TcpTransferTransport` (real `asyncio` sockets, length-prefixed
      AEAD-encrypted framing) is built and verified over real
      localhost sockets — see ADR-0017. Left unchecked because it's
      not wired into `main.py` yet: it needs a per-session key that
      nothing in this codebase currently negotiates between two real
      processes. `PacketType.HELLO`/`KEY_EXCHANGE`/`AUTH` are declared
      in `core/protocol.py` and `PycaKeyExchangeProvider` exists, but
      no handshake calls them. That handshake — and resolving
      `derive_session_keys`'s send/receive key-swap ambiguity as part
      of it — is what remains before `main.py` can sync with a real
      remote peer.
- [x] **Phase 12 — Key Exchange Handshake**
      `X25519Handshake` performs a real X25519 exchange over a real
      TCP connection and resolves the exact key-swap ambiguity Phase
      11 named: initiator and responder deterministically get
      complementary `(send_key, receive_key)` pairs — verified over a
      real socket (`initiator.send_key == responder.receive_key` and
      vice versa). Full chain verified end to end: handshake →
      negotiated keys (no hardcoded key) → real encrypted chunk
      transfer through the unmodified application use cases. See
      ADR-0018. The two gaps this entry originally disclosed — peer
      authentication, and wiring into `main.py`/`SyncOrchestrator` —
      are now both resolved; see Phase 13.
- [x] **Phase 13 — Peer Authentication and Full main.py Wiring**
      A persistent Ed25519 identity per device now signs every
      handshake message, and a trust-on-first-use store
      (`TrustedPeerRepository`) pins each peer's identity key across
      handshakes, rejecting a later handshake that presents a
      different key for an already-trusted `device_id` — verified
      with an actual impersonation attempt in this session (rejected).
      See ADR-0019. `TcpTransferTransport` was refactored from one
      fixed key pair to a `SessionKeyStore` (`device_id -> PeerSession`),
      so a device can hold independently-keyed sessions with multiple
      peers at once; the chunk-transfer port is exchanged as part of
      the handshake itself, not guessed from a convention.
      `SyncOrchestrator` gained an optional `session_coordinator` that
      establishes a session with each newly discovered peer, failing
      gracefully (logged, counted in `stats.errors_encountered`) if
      one peer's handshake fails without affecting others. `main.py`
      is now fully wired — real identity, real handshake server, real
      multi-peer transport, `download_use_case`/`upload_use_case` no
      longer `None` — verified by actually running `bootstrap()` in
      this session. See ADR-0020.
- [x] **Phase 14 — Manifest Exchange Protocol**
      `ManifestExchangeTransport` (real `TcpManifestExchangeTransport`
      implementation) lets one peer ask another "what do you have for
      this file?" — the one piece of information `DeltaCalculator`
      (Phase 3) needs to compute anything, and the last missing piece
      for genuine cross-machine sync. Reuses the already-negotiated
      session keys from the handshake (no separate key exchange) and
      serves manifests from the same `ChunkRepository`
      `ComputeDeltaUseCase` already reads baselines from. A third
      negotiated port (`manifest_port`) is exchanged the same way the
      transfer port is — as part of the signed handshake payload.
      Verified end to end: a request for a file the peer has returns
      its real manifest (chunk hash confirmed matching); a request for
      a file it doesn't have returns `None`. See ADR-0021. Not yet
      done: `SyncOrchestrator`'s automatic loop doesn't call this yet
      — establishing a session with a discovered peer doesn't yet
      trigger requesting its manifests, computing deltas, or
      transferring anything as a result. That orchestration loop is
      the next explicit step.
- [x] **Phase 15 — File Synchronization Use Case**
      `SyncFileUseCase.push`/`.pull` compose manifest exchange + delta
      computation + transfer into the first real "synchronize this
      file" operation. Building and verifying it against two real
      peer processes surfaced and fixed three genuine bugs: syncing a
      file that doesn't exist locally yet used to crash; an absolute
      local path can't identify a file across two machines with
      different filesystem layouts (fixed — every cross-peer
      reference is now relative to each side's own sync root); and a
      first automatic-bidirectional version silently overwrote a
      fresh local edit with a peer's stale copy of the same chunk
      (fixed by making `push`/`pull` separate, explicit-direction
      methods instead of one method that reconciles both ways —
      removing the ambiguity, not patching around it). Also required
      a genuine chunk-data *pull* (`ManifestExchangeTransport.request_chunks`)
      since `TransferTransport.request_chunks`'s "no real
      request/response round trip" limitation (disclosed back in
      ADR-0017/0018) turned out to hang forever the first time a real
      caller actually needed a pull. New `FileReconstructor` port
      writes downloaded chunks at their correct offset within the
      reconstructed file (deliberately not Phase 2's `ChunkWriter`,
      which writes a chunk as its own standalone file — the wrong
      shape for this). Verified end to end: fresh push, fresh pull, an
      incremental edit pushed and pulled (only the changed chunk
      transferred each way), and a final no-op push — file contents
      matched byte-for-byte throughout. See ADR-0022. Not yet done:
      deciding *which* direction is correct for a given file — real
      conflict detection wired to this path — is still the caller's
      job; `SyncOrchestrator` still doesn't call this automatically.

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
