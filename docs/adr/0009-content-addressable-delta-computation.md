# ADR 0009: Content-Addressable Delta Computation, Reusing the Phase 2 Chunk Cache

**Status:** Accepted
**Date:** Phase 3

## Context

`ROADMAP.md`'s Phase 3 entry is "Hash comparison, chunk cache, transfer
only changed chunks." Two design questions need settling before any
code is written:

1. **What counts as the "chunk cache"?** Phase 2 already shipped
   `ChunkRepository` (`domain/chunking.py`) — a port for saving and
   loading a file's `ChunkCollection` manifest by source path, with a
   filesystem-backed implementation (`FileChunkRepository`) explicitly
   documented as a placeholder for the Phase 8 SQLite store. A
   manifest of chunk hashes, keyed by file and swappable in storage
   technology, *is* a chunk cache in every sense the roadmap entry
   asks for.
2. **How should "changed" be decided — by position or by content?**
   `ChunkMetadata.chunk_id`'s own docstring (written in Phase 2)
   already anticipates this: *"a future Delta Sync / dedup phase
   compares `chunk_hash` values, never `chunk_id` values, across
   sources."* Comparing the *N*-th chunk of the baseline against the
   *N*-th chunk of the current manifest would be simpler to implement,
   but is fragile: any edit that shifts every following chunk's index
   (an insertion near the start of the file, under fixed-size
   chunking) would make *every subsequent chunk* look changed, even
   though most of their bytes are identical to a chunk that still
   exists in the baseline — just at a different index.

## Decision

**No new cache.** `ComputeDeltaUseCase` (`application/use_cases/compute_delta.py`)
takes an injected `ChunkRepository` and calls `.load(path)` to fetch
the baseline manifest (`None` on a file's first sync). It never
constructs a second cache or a new port for this purpose.

**Content-addressable matching.** `DeltaCalculator` (`domain/delta.py`)
is a stateless domain service: `compute(baseline, current) -> DeltaPlan`.
It builds a `frozenset[ChunkHash]` of every hash present anywhere in
`baseline` and classifies each chunk of `current` as `ChunkAction.REUSE`
if its hash is in that set, `ChunkAction.TRANSFER` otherwise — an O(1)
membership test per chunk after an O(n) set build, with no dependency
on either manifest's chunk count matching or on which
`ChunkingStrategy` produced either one. A chunk that moved position
(content shifted elsewhere in the file) or was produced by a
differently-configured strategy run is still recognized as reusable
as long as its bytes, and therefore its hash, are unchanged.

**Read-only use case.** `ComputeDeltaUseCase.execute` returns a
`DeltaPlan` (which carries `plan.current`, the freshly built manifest)
but never calls `repository.save(...)` itself. Updating the baseline
is the caller's explicit, separate step. This phase has no Transfer
Engine yet (`Phase 5`, still `[ ]` in `ROADMAP.md`) — persisting a new
baseline before the chunks in `plan.chunks_to_transfer` have actually
reached a peer would let the cache claim content is already
synchronized when it might not be.

## Consequences

**Positive**

- Zero new infrastructure: `FileChunkRepository` from Phase 2 is
  reused unchanged as the chunk cache, exactly as its own docstring
  ("the port stays the same either way") anticipated.
- Content-addressable matching means Phase 3's design already
  accommodates a future content-defined `ChunkingStrategy`
  (ADR-0007) without any change to `DeltaCalculator` — CDC's whole
  point is that chunk boundaries (and therefore indices) shift as
  content is inserted or deleted elsewhere in the file, which
  position-based matching would have handled poorly.
- `DeltaCalculator` has no I/O and no `asyncio` import, consistent
  with ADR-0008's synchronous-domain-core pattern; only
  `ComputeDeltaUseCase`'s repository read is wrapped in
  `asyncio.to_thread`.
- Keeping the use case read-only means a caller that fails partway
  through transferring `plan.chunks_to_transfer` (once Phase 5 exists)
  can simply not call `repository.save(plan.current)` — no
  compensating "undo the cache update" logic is ever needed, because
  the update never happened speculatively in the first place.

**Negative / trade-offs accepted**

- Building `frozenset[ChunkHash]` costs memory proportional to the
  baseline's chunk *count* (never chunk content, consistent with
  `ChunkCollection`'s own memory model) — a few hundred thousand small
  hash records for any realistic chunk size and file size, not a
  concern for Phase 3's scope.
- Hash-set matching cannot distinguish "this exact chunk, at this
  exact position, is unchanged" from "some chunk somewhere in the
  baseline happens to have identical bytes" (e.g. a run of zero bytes,
  or a duplicated block). Both are legitimately reusable — the peer
  already has those bytes under some existing chunk it can serve from
  — but a future phase that needs to reconstruct the file byte-for-byte
  from reused chunks (the Transfer Engine, Phase 5) must resolve *which*
  baseline chunk to reuse when several share a hash, not just *whether*
  to reuse one. Out of scope here: `DeltaPlan` only classifies the
  *current* file's chunks; it does not yet produce a byte-level
  reconstruction recipe.
- No tombstoning of removed content: `DeltaPlan` doesn't report chunks
  present in `baseline` but absent from `current` (e.g. the file
  shrank). Not needed for "transfer only changed chunks" — Phase 3's
  literal scope — but a full sync/reconciliation use case in a later
  phase will need that information too, and can compute it the same
  way (`baseline_hashes - current_hashes`) without any change to
  `DeltaCalculator`.

## Rejected: index-based (positional) diffing

Compare `baseline.chunks[i]` against `current.chunks[i]` for each
shared index; treat any index beyond the shorter collection's length
as pure append/truncate. Simpler to implement and reason about for
the common case (an in-place edit that doesn't shift any chunk's
position), but produces false positives — flagging chunks as changed
when their bytes are actually identical, just relocated — on any edit
that shifts chunk boundaries, and gives no natural extension path to
content-defined chunking, where boundaries shifting on every edit is
the normal case rather than a rare one.

## Rejected: a new `ChunkCache` port distinct from `ChunkRepository`

Would duplicate `ChunkRepository`'s `save`/`load`-by-source-path
contract under a new name for no behavioral difference, violating
DRY and YAGNI. If a future need genuinely diverges from
`ChunkRepository`'s shape (e.g. a cache keyed by hash rather than by
file, for cross-file deduplication), that's a new port introduced
when that need is concrete — not speculatively now.
