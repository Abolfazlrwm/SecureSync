# ADR 0005: SQLite for Metadata Storage

**Status:** Accepted
**Date:** Phase 0

## Context

Each SecureSync device needs to persist metadata: known peers, chunk
hashes, file versions, sync history, and statistics. This store is local
to a single device — it is never accessed concurrently by another process
across the network.

## Decision

Use `sqlite3` from the Python standard library as the metadata store,
accessed exclusively through a `Repository`-pattern adapter in
`infrastructure/` (see `docs/architecture.md` §4).

## Consequences

**Positive**
- Zero operational overhead — no database server to install, configure, or
  monitor; fits a tool meant to run unattended on a user's own device.
- Transactional guarantees (ACID) matter here: chunk/version bookkeeping
  must not be left in a half-updated state after a crash mid-sync.
- Standard library — no new runtime dependency.

**Negative / trade-offs accepted**
- Single-writer limitation is irrelevant for this use case (one SecureSync
  process owns its own metadata file) but would be a real constraint if
  the architecture ever needed multiple local processes writing metadata
  concurrently — not a planned requirement.
- All access goes through the `PeerRepository` / `ChunkRepository` /
  `HistoryRepository` ports so that if this decision ever needs revisiting
  (e.g. a future embedded key-value store), only the `infrastructure/`
  adapters change — `application/` and `domain/` are unaffected.

## Rejected: embedded key-value store (e.g. LMDB, RocksDB)

Rejected for Phase 0 — SQLite's relational model maps naturally onto the
actual query needs here (e.g. "all chunks for file X", "all files last
synced with peer Y"), and adding a KV store would mean re-implementing
indexing/query logic that SQLite already provides.
