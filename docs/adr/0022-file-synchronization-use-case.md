# ADR 0022: File Synchronization — Explicit Push/Pull, Not Automatic Bidirectional

**Status:** Accepted
**Date:** Post-Phase-14 follow-up

## Context

Phase 14 built a real manifest exchange; nothing yet composed it with
delta computation and transfer into an actual "synchronize this file"
operation. Building `SyncFileUseCase` and verifying it against two
real peer processes surfaced three genuine bugs — not edge cases found
by inspection, but ones that reproduced with a real, non-contrived
two-device test scenario, in the order they were found:

1. **Syncing a file that doesn't exist locally yet crashed.** The
   ordinary "first pull" case — the peer has a file, this device
   doesn't — made `CalculateChunkHashesUseCase.build_manifest` raise
   `ChunkSourceNotFoundError` before any comparison could happen.
2. **An absolute local path can't be a cross-machine file identifier.**
   `ManifestExchangeTransport.request_manifest` originally took a raw
   path string. Two peers' sync directories live at different
   absolute locations (`/tmp/tmpXXXX_A/shared.txt` vs.
   `/tmp/tmpXXXX_B/shared.txt` even in the test; `C:\Users\Alice\Sync\`
   vs. `/home/bob/sync/` in reality) — a manifest saved under one
   peer's absolute path is invisible to a lookup by the other peer's
   absolute path, silently returning "not found" for a file the peer
   genuinely has.
3. **Automatic bidirectional sync silently corrupted a fresh edit.**
   Fixing (1) and (2) enabled a full round trip, which then revealed
   the deepest issue: `TransferTransport.request_chunks` (the
   `TcpTransferTransport` "pull") never actually asks the peer for
   anything — it only reads whatever the peer already chose to push
   (ADR-0017/0018's own disclosed limitation, only now actually
   exercised by a real caller) — so a naive "pull" call hung forever
   waiting for chunks nobody would ever send. Working around that with
   a real request/response pull then exposed a worse problem: without
   any timestamp or version signal, a pure content-hash diff cannot
   tell "I have new content the peer needs" apart from "I have stale
   content the peer has already moved past" — both look identical to
   `DeltaCalculator`. An automatic "push what's missing, then pull
   what's missing" in one call reliably overwrote a device's own fresh
   edit with the peer's stale copy of the same chunk, verified with an
   actual round-trip test that ended in `file_a != file_b`.

## Decision

**All three were fixed as real bugs, not deferred:**

1. `SyncFileUseCase._local_manifest_or_empty` catches
   `ChunkSourceNotFoundError` and treats a missing local file as an
   empty manifest — a legitimate starting state for a pure pull, not
   an error.
2. Every cross-peer file reference — `ManifestExchangeTransport`'s
   `request_manifest`/`request_chunks`, and `SyncFileUseCase`'s own
   parameters — now takes a path *relative to each side's own sync
   root*, never absolute. `TcpManifestExchangeTransport` takes a new
   `sync_root: Path` constructor parameter specifically to resolve an
   incoming relative path back to this device's own absolute one
   before consulting its local `ChunkRepository`.
   `DeltaCalculator`'s own `baseline.source_path == current.source_path`
   invariant (ADR-0009 — correct for its original, purely-local
   design) still needed the peer's manifest normalized to this
   device's own absolute path before comparison;
   `SyncFileUseCase._normalized_peer_manifest` does that with
   `dataclasses.replace`, keeping `DeltaCalculator` itself unchanged.
3. `ManifestExchangeTransport` gained a genuine
   `request_chunks(peer, relative_path, chunk_hashes)` pull:
   the requester actively asks, and the responder reads the exact
   requested byte ranges from its own copy of the file (via the
   already-known chunk offsets in its saved manifest) and answers on
   the same connection — the same request/response shape
   `request_manifest` already used, not `TransferTransport`'s
   push-only inbox. **`SyncFileUseCase.push` and `SyncFileUseCase.pull`
   are separate, explicit-direction methods** rather than one method
   that reconciles both ways automatically — removing the ambiguity
   that caused bug 3 entirely, rather than attempting a heuristic
   patch over it. Verified end to end after all three fixes, across a
   full scenario a heuristic-only fix would not have caught: fresh
   push, fresh pull, an edit pushed and pulled incrementally (only the
   changed chunk transferred each way), and a final no-op push
   (zero chunks) — file contents matched byte-for-byte throughout.

**`FileReconstructor`** (`domain/reconstruction.py`,
`infrastructure/chunking/local_file_reconstructor.py`) is a new,
narrow port: write one chunk's bytes at its offset within a larger
file being reconstructed. Deliberately not
`~securesync.domain.chunking.ChunkWriter` (Phase 2) — that port writes
a chunk's bytes as its own standalone file, the wrong shape for
writing into one reconstructed target file at a byte offset. Verified:
out-of-order chunk writes reassemble correctly, and writing one chunk
never disturbs bytes belonging to others already written.

## Consequences

**Positive**

- Every fix in this ADR was caught by an actual two-process test
  scenario, not by static reasoning about what *might* go wrong —
  consistent with this project's standard of verifying claims rather
  than asserting them.
- Explicit `push`/`pull` means `SyncFileUseCase` can never itself
  cause the data-loss bug found in this session: either method touches
  only one direction, full stop.
- The relative-path fix generalizes correctly beyond this one bug —
  any future cross-peer file reference in this codebase should use
  the same convention, now established and documented here.

**Negative / trade-offs accepted**

- **Deciding which direction is correct for a given file is still
  entirely the caller's job**, and nothing in this codebase makes that
  decision yet — `SyncOrchestrator`'s automatic loop still doesn't call
  `SyncFileUseCase` at all (this ADR's scope was the use case itself,
  proven correct in isolation, not the orchestration that would invoke
  it automatically for every discovered peer and every synced file).
  Making that automatic requires real conflict detection (version
  vectors, Phase 7's `DetectConflictUseCase`, not yet wired to this
  path) to choose push vs. pull vs. "these genuinely conflict, ask the
  user" — deliberately not decided here.
- `push` always overwrites the remote peer's version of any chunk it
  differs on; `pull` always overwrites the local version. Correct only
  when the caller already knows which side should win — true for a
  deliberate one-way sync, not true for reconciling two sides that
  both changed independently.
- No conflict is ever *detected*, only avoided by never attempting
  both directions in one call. A genuine two-way conflict (both peers
  edited the same file differently) isn't flagged; it just doesn't
  cause corruption within a single `push` or `pull` call — a future
  caller doing both directions across separate calls could still
  clobber a peer's independent edit, exactly as `push` is documented
  to do.

## Rejected: keep automatic bidirectional sync, add a heuristic guard

An earlier version of this use case added "skip download if this call
also uploaded something" as a guard. Verified insufficient in this
session: the same structural ambiguity corrupts the *upload* decision
too (a device can compute that it should push its own stale chunk back
to the peer, overwriting the peer's fresh edit), not just the download
one — a symptom of the same missing information, not two independent
bugs each fixable by its own patch. Removing the automatic
reconciliation entirely, rather than special-casing around it, was the
fix that actually held up under the full round-trip test.

## Rejected: relax `DeltaCalculator`'s same-source-path invariant

Would let `SyncFileUseCase` pass the peer's manifest straight through
without normalizing its path first, but that invariant is correct and
valuable for `DeltaCalculator`'s original purely-local use (ADR-0009)
— it's a real bug to accidentally diff two different files. The
mismatch here is specific to the *cross-machine* case having two
different "same file," which is exactly what normalizing the path
before comparison resolves without weakening the check for every other
caller.
