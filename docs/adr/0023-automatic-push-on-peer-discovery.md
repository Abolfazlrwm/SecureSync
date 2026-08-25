# ADR 0023: Automatic Push on Peer Discovery, Deferring "Is It Actually Newer" to Phase 17

**Status:** Accepted
**Date:** Post-Phase-15 follow-up

## Context

ADR-0022 built `SyncFileUseCase.push`/`pull` and proved each direction
correct in isolation, but left `SyncOrchestrator.handle_peer_discovered`
calling neither — a peer was tracked and session-established, then
nothing further happened. Wiring the two together needs an answer to
one specific question first: when a peer is discovered, on what basis
does the orchestrator decide a local file should be pushed?

The obvious-looking answer — compare local `FileMetadata.last_modified`
or `version_vector` against the peer's — isn't available yet.
`ManifestExchangeTransport` (the only channel this codebase has for
asking a peer about a file) returns a `ChunkCollection`: chunk hashes
and offsets, nothing else. No `FileMetadata`, no version vector, ever
crosses the wire. Building that exchange is exactly Phase 7's
`DetectConflictUseCase` becoming reachable over the network — deferred
by ADR-0022 and still not done.

## Decision

**Push every locally known, non-deleted file to a newly discovered
peer, unconditionally — and let `SyncFileUseCase.push`'s own manifest
diff decide whether that's a no-op.**

`push` already requests the peer's manifest and only transfers chunks
the peer is actually missing (ADR-0022). A peer that's already fully
synced on a given file costs one manifest round trip and zero chunk
transfers. This makes "push automatically" well-defined without
needing remote version metadata this codebase doesn't have yet:
"newer" is approximated as "the peer is missing chunks I have," which
is the only signal actually available over the wire today.

`SyncOrchestrator.handle_peer_discovered` gained a private
`_auto_push_known_files` step, run after session establishment:
iterates `metadata_repo.list_all_files()`, skips anything
`is_deleted`, and calls `push()` per file. One file's push failing
(peer went offline mid-batch, file deleted from disk after being
recorded, etc.) is logged and counted in `SyncStats.errors_encountered`
without aborting the rest of the batch — consistent with how a failed
`session_coordinator.ensure_session` is already handled in the same
method.

`sync_file_use_case`, `sync_root`, `chunking_strategy`, and
`chunk_size` are new optional constructor parameters, following the
existing `download_use_case`/`upload_use_case` pattern: omitting them
reproduces the exact pre-Phase-16 behavior (peers tracked, nothing
synced). If `sync_file_use_case` is set but any of the other three
is missing, `_auto_push_known_files` logs a warning and returns rather
than raising — a wiring mistake in a composition root shouldn't crash
peer discovery for every other peer.

## Consequences

**Positive**

- Files reach a newly discovered peer without any manual step, closing
  the gap this ADR set out to close.
- No new network protocol or remote-metadata exchange needed — reuses
  exactly the manifest diff ADR-0022 already proved correct.
- The pre-Phase-16 default (no `sync_file_use_case` configured) is
  unchanged, verified by a dedicated regression test.

**Negative / trade-offs accepted**

- **This is not conflict-aware.** "The peer is missing chunks I have"
  cannot distinguish a genuine local edit from a local device that's
  simply behind — pushing in that second case would silently overwrite
  the peer's newer content with this device's stale copy.
  `DetectConflictUseCase` (Phase 7) is still not wired into this path;
  doing so is Phase 17's entire scope, not addressed here.
- Every discovered peer gets every locally known file pushed at
  discovery time, even ones that were already fully synced moments
  ago (e.g. a peer briefly dropping offline and reappearing). The
  manifest-diff no-op keeps this cheap, not free — one manifest
  request per file, per rediscovery.
- A file that fails to push is only logged, not retried. Phase 19's
  retry/backoff work covers connection-level retries; a file skipped
  for another reason (e.g. deleted from disk) isn't picked up again
  until the next time this peer is (re)discovered.

## Rejected: wait for Phase 17 and wire both together

Would avoid ever pushing a file the peer's own edit should have taken
precedence over. Rejected because Phase 16 was scoped, deliberately,
to auto-push without conflict detection — folding Phase 17 in here
would just be doing Phase 17 under Phase 16's name. The risk above is
accepted explicitly and short-lived: it closes as soon as Phase 17
lands `DetectConflictUseCase` on this same path.

## Rejected: compare local `last_modified` against the peer's last-seen timestamp

`DiscoverPeersUseCase` already knows when a peer was last seen online,
which looks like it could stand in for "how stale is their copy."
Rejected — a peer's online/offline timestamp says nothing about *which
file version* it holds; a peer offline for five minutes could still
have the newer copy of a specific file edited on a third device before
it went offline. Using it would trade one unfounded heuristic for
another, without removing the real gap: no version data for the file
itself crosses the wire yet.
