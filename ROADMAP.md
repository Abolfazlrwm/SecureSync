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
- [ ] **Phase 2 — Chunk Engine**
      Configurable chunk size, rolling hash, SHA-256, chunk metadata
      (Merkle tree support reserved for a later phase).
- [ ] **Phase 3 — Delta Synchronization**
      Hash comparison, chunk cache, transfer only changed chunks.
- [ ] **Phase 4 — Peer Discovery**
      UDP broadcast, mDNS, peer cache, heartbeat, reconnect logic.
- [ ] **Phase 5 — Transfer Engine**
      Async TCP + TLS, streaming, resumable transfers, integrity
      validation, compression, parallel transfers.
- [ ] **Phase 6 — End-to-End Encryption**
      X25519 key exchange, AES-256-GCM / ChaCha20-Poly1305, nonce
      management, session keys, key rotation.
- [ ] **Phase 7 — Conflict Resolution**
      Timestamp + version metadata, conflict files, vector-clock-ready
      design.
- [ ] **Phase 8 — Metadata Database**
      SQLite schema for peers, chunks, hashes, versions, history, stats.
- [ ] **Phase 9 — CLI Dashboard**
      Typer commands, Rich live dashboard, progress bars, logs, peer
      status.
- [ ] **Phase 10 — Configuration System**
      YAML + environment variables, validation, hot reload.

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
- Multi-language client implementations
