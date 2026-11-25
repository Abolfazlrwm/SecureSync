# ADR 0024: Version-Aware Sync Direction

**Status:** Accepted
**Date:** 2026-08-27

## Context

ADR-0023 deferred automatic sync direction (push vs. pull) because
auto-push only implemented pushing on peer discovery. The
`SyncOrchestrator._auto_push_known_files` method pushes every known
file to a newly discovered peer unconditionally, relying only on
`SyncFileUseCase.push`'s manifest diff to no-op when nothing is
missing. That means direction is never actually decided — it's always
push. When the peer's copy is newer (the common case on a second
device joining the network), the push is a no-op that does nothing.
Pulls never happen automatically; the peer would need to run the
orchestrator's sync loop independently.

A real direction signal requires comparing **who has the newer version**,
not just who has different chunk hashes. Without that signal, the system
can't tell:
- "I have new content the peer needs" (push)
- "The peer has new content I need" (pull)
- "Both of us edited independently" (conflict)
- "Nothing changed" (noop)

The conflict layer built `VersionVector` for exactly this purpose,
and the SQLite store persisted it via `MetadataRepository`. The manifest
exchange already returned `ChunkCollection` from peers. The missing link
was passing the `VersionVector` through that same manifest exchange
without requiring a second round trip.

### The msgpack type-stub regression (lesson learned)

During implementation a `sed` command intended to remove an unused
`# type: ignore[import-untyped]` comment from `presentation/cli.py`
matched too broadly and also stripped the **legitimate** `# type: ignore[import-untyped]`
comment from `import msgpack` in three other files (`core/protocol.py`,
`infrastructure/networking/x25519_handshake.py`,
`infrastructure/networking/tcp_manifest_exchange.py`). This produced
three new mypy errors that had nothing to do with this change,
and took several minutes to trace back to the over-matching `sed`.

The lesson: when removing a `type: ignore` comment by pattern, pin
the match to the specific import line (`import yaml`), not a generic
pattern that could affect other untyped imports in the same codebase.

## Decision

### 1. Manifest responses now include `VersionVector`

`ManifestExchangeTransport.request_manifest` (domain port +
`TcpManifestExchangeTransport` implementation) now returns a new
`ManifestWithVersion` dataclass pairing the peer's `ChunkCollection`
with an optional `VersionVector`. The version comes from a
`MetadataRepository` (SQLite-backed in production); when none is
configured (legacy setups, tests) the version is reported as `None`
and the caller falls back to content-hash-only direction decisions.

The `TcpManifestExchangeTransport` gains an optional
`metadata_lookup` constructor parameter for this purpose. When `None`
(the default), the transport continues to work identically to
auto-push — no migration required for existing wiring.

### 2. `SyncDirectionResolver` — a stateless domain service

A new `SyncDirectionResolver` in `domain/sync_direction.py` compares
local vs. remote `VersionVector` using the `happens_before`/`concurrent`
logic, and returns one of four outcomes:

- **PUSH** — local version strictly newer than remote.
- **PULL** — remote version strictly newer than local.
- **CONFLICT** — versions are concurrent (neither is an ancestor);
  falls back to `LastWriterWinsStrategy`.
- **NOOP** — vectors are equal (or both empty); content-hash
  comparison breaks the tie.

**Fallback when the peer has no VersionVector:** When the peer
reports `None` for its version (a device that records no versions, a test that
doesn't seed versions, or a peer that doesn't persist metadata),
the resolver falls back to the content-hash-only comparison that
the earlier sync flows did. This means CONFLICT can't be detected
without a version, so the fallback never returns CONFLICT — it
defaults to PUSH for any content mismatch, matching the
auto-push behavior. This is a deliberate trade-off: the fallback
is correct but less precise than the version-aware path.

### 3. `SyncFileUseCase.sync()` — orchestrates the full flow

A new `sync()` method on `SyncFileUseCase` composes the full
sequence: request peer manifest → resolve direction → push / pull /
noop / conflict. On CONFLICT, it falls back to `LastWriterWinsStrategy`
rather than crashing — "remote wins" pulls the peer's
version; "local wins" no-ops. The `merge_strategy` parameter accepts
a custom policy; default is `LastWriterWinsStrategy()`.

The orchestrator's `_auto_push_known_files` loop now calls `sync()`
instead of `push()`, so newly discovered peers trigger direction-aware
sync automatically.

### 4. Tests exercise all four outcomes

The new `SyncDirectionResolver` is tested against all four outcomes
(PUSH, PULL, CONFLICT, NOOP) using real in-process manifest
exchanges — reusing the existing test patterns from the sync use case.
The `FakeManifestExchangeTransport` in `tests/doubles.py` was
updated to return `ManifestWithVersion` (with an optional
`versions` dict for seeding version vectors), and all existing
tests that used the old `ChunkCollection` return type were updated
accordingly.

## Consequences

1. **One round trip instead of two.** The peer's version vector
   travels with the manifest response — no separate metadata query
   needed to decide sync direction.

2. **Backward compatible.** Peers that don't report a version vector
   (version-less peers, test doubles) continue to work via
   the content-hash fallback. No migration required.

3. **Conflict handling is automatic.** When two peers independently
   edit the same file, the resolver detects the concurrent versions
   and the `LastWriterWinsStrategy` policy picks one direction —
   no crash, no manual resolution required (for now).

4. **The TCP transport's `send_chunk` key-lookup was fixed as a
   side effect.** This work surfaced that `TcpTransferTransport`
   was looking up the peer's session to find encryption keys, but
   the shared inbox doesn't track which peer sent each envelope.
   This was corrected to use own device's keys (fixed in the same
   commit that introduced the resolver, but technically a pre-existing
   bug unrelated to version-aware direction).

5. **msgpack type-stub comment restoration.** An over-matching
   `sed` command stripped `# type: ignore[import-untyped]` from
   `import msgpack` in three files, producing three new mypy errors.
   This was fixed and documented here as a lesson: always pin
   `sed` patterns to the specific target, not a generic substring
   that can affect adjacent code.
