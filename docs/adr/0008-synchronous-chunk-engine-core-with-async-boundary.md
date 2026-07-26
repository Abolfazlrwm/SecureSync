# ADR 0008: Synchronous Chunk-Engine Core with an Async Use-Case Boundary

**Status:** Accepted
**Date:** Phase 2

## Context

Every use case shipped in Phase 1 (`MonitorDirectoriesUseCase`) is
`async def`, because `watchdog` delivers filesystem events from its own
background thread — the application layer's job there is to bridge
that thread's output into the asyncio event loop.

The chunk engine's core work — reading a file and hashing its bytes —
is different in kind: it's local, synchronous, CPU/IO-bound work with
no external thread already doing it. Writing `StreamingChunkReader`
and `SHA256HashProvider` as `async def` using plain blocking calls
underneath (`file.readinto()`, `hashlib.update()`) would not make them
non-blocking; it would only make the blocking visible one layer later,
stalling the event loop for the duration of every read or hash exactly
as if they were called synchronously, while looking async at a glance.
Doing the block-avoidance correctly inside the reader itself (e.g.
`loop.run_in_executor` calls scattered through `_stream_chunks`) would
tie infrastructure code to the asyncio runtime for no benefit, since
generators are already the natural, directly testable shape for lazy,
bounded-memory iteration.

## Decision

`domain.chunking` ports, `StreamingChunkReader`, `SHA256HashProvider`,
`ChunkFileWriter`, and `FileChunkRepository` are all synchronous
(`Iterator`-based, not `AsyncIterator`-based). None of them import
`asyncio`.

`ChunkFileUseCase`, `VerifyChunkUseCase`, and
`CalculateChunkHashesUseCase` (application layer) are `async def`, to
stay consistent with the rest of the application layer and with
whatever calls them (a future CLI or sync engine will itself be
async). Where a use case needs to run the synchronous core without
blocking the event loop, it does so via `asyncio.to_thread`:

- `VerifyChunkUseCase` calls `asyncio.to_thread(hasher.hash, data)`
  directly for its single blocking call.
- `ChunkFileUseCase` and `CalculateChunkHashesUseCase` drive their
  multi-step read-then-hash generators through
  `utils.async_iter.iter_in_thread` — a small, generic bridge
  (`domain`- and chunk-engine-agnostic) that runs each `next()` call on
  the underlying generator via `asyncio.to_thread`, yielding items back
  to the caller one at a time so memory stays bounded by a single
  chunk, never the whole sequence.

## Consequences

**Positive**

- Every chunk-engine adapter is testable with a plain synchronous
  `pytest` test — no event loop, no `pytest-asyncio`, no mocking
  `asyncio.to_thread` — which is exactly how `tests/unit/infrastructure/chunking/`
  and `tests/chunking/` are written.
- The event loop is never blocked by file I/O or hashing, confirmed
  directly in `tests/unit/utils/test_async_iter.py`
  (`test_iteration_runs_off_the_calling_thread`), not just asserted in
  a docstring.
- `iter_in_thread` has no chunk-engine-specific dependency, so a future
  phase (Delta Sync's rolling-hash scan, the Transfer Engine's local
  disk reads) that needs the same "blocking generator, async caller"
  bridge can reuse it directly from `utils/` instead of re-deriving the
  pattern.
- Peak memory stays bounded by one chunk even across the async
  boundary: `iter_in_thread` never gathers results into a list before
  yielding.

**Negative / trade-offs accepted**

- Two execution models exist side by side in this phase (sync core,
  async use case), which is one more thing for a new contributor to
  learn than "everything is async" would have been — mitigated by
  `ADR-0002`'s existing precedent (asyncio is already the project's
  chosen runtime, so the *use case* layer being async is unsurprising)
  and by this ADR documenting the split explicitly.
- `asyncio.to_thread` uses the default thread pool executor, which has
  a bounded worker count; a very large number of concurrent
  `ChunkFileUseCase.execute()` calls could contend for threads. Not a
  concern for Phase 2 (a single file is chunked by a single caller);
  worth revisiting once Phase 5 (Transfer Engine) needs many
  concurrent chunking operations.
- **Measured cost**: each chunk crosses one `asyncio.to_thread` round
  trip. On a 200MB file at the default 4 MiB chunk size (50 chunks),
  going through `ChunkFileUseCase` measured ~1.4x slower end-to-end
  than calling `StreamingChunkReader`/`SHA256HashProvider` directly in
  a synchronous loop (see the measurement in the Phase 2 PR
  description) — real overhead, not zero-cost abstraction. Acceptable
  for Phase 2 (a single file's chunking is not the system's throughput
  bottleneck; disk I/O and, later, network transfer dominate). If a
  future phase's profiling shows this mattering, the fix is batching —
  have `iter_in_thread` (or a chunk-engine-specific variant) drain
  several chunks per `to_thread` call instead of one — not abandoning
  the sync-core design; not implemented now because Phase 2 has no
  caller for whom it's the bottleneck.

## Rejected: fully `async def` core (`async for chunk in reader.read_chunks(...)`)

Would require either delegating every blocking call to
`run_in_executor` inside the reader/hasher themselves (coupling
infrastructure code to asyncio for no correctness benefit, since the
work is still fundamentally synchronous) or, worse, leaving the calls
truly blocking inside an `async def` (which blocks the event loop while
looking safe). Neither improves on a synchronous core with the
`async`/`to_thread` boundary pushed to the application layer, where it
belongs per Clean Architecture's dependency rule — the domain and
infrastructure stay technology-plain, and only the application layer
knows about the asyncio runtime it's composed into.

## Rejected: fully synchronous use cases (no `async def` at all)

Would be simpler for Phase 2 in isolation, but breaks the calling
convention every other use case in the codebase follows
(`MonitorDirectoriesUseCase`), and would force a future presentation
layer (CLI, Transfer Engine) that's already `async` throughout to special-case
calling the chunk engine synchronously — likely via its own
`asyncio.to_thread` wrapper anyway, just written once per call site
instead of once here.
