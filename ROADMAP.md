# Roadmap

## What works today

- **Filesystem watching** - recursive monitoring of multiple directories
  (create/modify/delete/rename/move) with debouncing and async dispatch,
  via a `watchdog` adapter behind a domain port.
- **Chunk engine** - streaming, bounded-memory chunking (fixed-size by
  default, 4 MiB, configurable) with SHA-256 hashing. The chunking
  strategy is a pluggable port, so content-defined chunking (FastCDC or
  similar) can slot in later without touching callers.
- **Delta sync** - content-hash comparison of a file's current chunks
  against the recorded baseline, so only changed chunks are transferred.
- **Peer discovery** - mDNS via zeroconf, with online/offline tracking.
- **Transfer engine** - a binary wire protocol (32-byte header, MessagePack
  payload) over real asyncio TCP sockets, with replay-protected v2 frames.
- **Encryption** - X25519 key exchange with HKDF-derived per-direction
  session keys, AES-256-GCM and ChaCha20-Poly1305 AEAD ciphers.
- **Peer authentication** - persistent Ed25519 identity per device,
  trust-on-first-use pinning, handshake rate limiting, and a signed
  handshake payload that also exchanges the transfer and manifest ports.
- **Conflict resolution** - version vectors for causal tracking, conflict
  detection, and pluggable merge strategies (last-writer-wins today).
- **Metadata** - SQLite-backed store for files, chunks, and version
  history, plus JSON manifests as the chunk cache.
- **Orchestration** - a sync orchestrator that reacts to discovered peers,
  resolves sync direction per file (PUSH/PULL/CONFLICT/NOOP from version
  vectors), and drives push, pull, and automatic sync.
- **Push receiver** - an unsolicited pushed chunk is decrypted, written at
  the right offset, and the file is finalized once complete, all without
  a manual step on the receiving side.
- **Runtime** - YAML configuration, application bootstrap, structured
  logging, graceful shutdown with signal handling, a CLI, and a Docker
  image.
- **Verification** - an end-to-end test that runs two fully bootstrapped
  instances over real TCP, plus property-based tests for the decoders and
  chunking, and security tests for path traversal, replay, and handshake
  impersonation. 732 tests, 95% coverage.

## In progress

- Wiring the filesystem watcher into the daemon loop so a saved file
  syncs without an explicit `securesync sync` call.

## Next up

- Wire the watcher into the daemon (above), with a debounce-to-sync
  pipeline that reuses the existing use cases.
- Compression before encryption.
- Resumable transfers for large files and flaky links.
- Bandwidth/rate limiting.
- Per-peer and per-file statistics in the CLI dashboard.

## Out of scope for now

- Merkle tree chunk verification (the chunk port leaves room for it, but
  plain SHA-256 per chunk is sufficient at current scale).
- Content-defined chunking (reserved behind the `ChunkingStrategy` port).
- CRDT-style merging of concurrent edits to the same file.
- Multi-language client implementations.
- NAT traversal and relaying; SecureSync targets machines that can reach
  each other directly on the network.
