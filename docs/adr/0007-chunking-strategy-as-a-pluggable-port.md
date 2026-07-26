# ADR 0007: Chunking Strategy as a Pluggable Port (Strategy Pattern)

**Status:** Accepted
**Date:** Phase 2

## Context

`ROADMAP.md`'s original Phase 2 entry listed "rolling hash" alongside
SHA-256 as a Phase 2 deliverable. The actual Phase 2 scope, confirmed
before implementation began, is narrower: fixed-size chunking only,
with content-defined chunking (rolling hash / Rabin fingerprint /
FastCDC) explicitly deferred. That narrowing needs to be reflected in
both the roadmap and the code, without boxing a future phase into a
rewrite.

Fixed-size chunking decides a chunk's boundary from size alone — it
never needs to look at the file's actual bytes. Content-defined
chunking is fundamentally different: it decides a boundary by
inspecting the byte stream itself (a rolling hash or fingerprint over a
sliding window signals a cut point), which means whatever abstraction
`StreamingChunkReader` depends on to find boundaries has to be able to
express both kinds of algorithm without changing shape.

## Decision

Introduce `ChunkingStrategy` (`domain/chunking.py`) as an abstract port
implementing the Strategy pattern, with exactly one concrete
implementation shipped in Phase 2: `FixedSizeChunkingStrategy`
(`infrastructure/chunking/streaming_chunk_reader.py`).

The port is pull-based rather than size-based:
`next_cut(buffered: memoryview, *, at_eof: bool) -> int | None`. A
strategy is handed every byte accumulated so far for the chunk
currently being assembled and answers how many of those leading bytes
belong to the current chunk, or `None` to request more data first.
`StreamingChunkReader` owns all actual file I/O — a strategy never
reads from disk itself — and drives this loop, reading in bounded
blocks and feeding the accumulated buffer to the strategy after each
read.

This shape works unchanged for a future content-defined strategy: a
`RollingHashChunkingStrategy` would scan `buffered` for a fingerprint
condition instead of comparing its length to a fixed target, but the
method signature, the reader's driving loop, and every application/
domain type built on top of `Chunk` and `ChunkMetadata` stay exactly as
they are today.

A second, non-abstract hook, `preferred_read_block_size`, lets a
strategy hint how much the reader should read per I/O call (defaulting
to 1 MiB, sized for a rolling window; `FixedSizeChunkingStrategy`
overrides it to match its configured chunk size) without forcing every
future strategy to implement it.

## Consequences

**Positive**

- A future `RollingHashChunkingStrategy`, `RabinFingerprintChunkingStrategy`,
  or `FastCDCChunkingStrategy` is a new adapter behind an existing port
  (Open/Closed) — zero change to `ChunkReader`, `ChunkFileUseCase`,
  `CalculateChunkHashesUseCase`, or any domain type.
- `StreamingChunkReader` stays free of any `isinstance` check against a
  concrete strategy type; it only ever calls the port's two members.
- Fixed-size chunking (the only algorithm Phase 2 ships) pays no
  runtime cost for this generality beyond one extra method call per
  read iteration — the pull-based loop is exactly how a real
  content-defined algorithm has to be structured anyway, so nothing
  here is speculative complexity that a future phase would need to
  undo.

**Negative / trade-offs accepted**

- The pull-based `next_cut` signature is less immediately obvious than
  a hypothetical `chunk_size_for(remaining_bytes: int) -> int` would
  have been for the fixed-size case alone — but that simpler shape
  cannot express content-defined chunking at all, so it would have
  been a false economy: Phase 3's rolling-hash work would have had to
  replace the port anyway.
- `ROADMAP.md` and `docs/architecture.md` needed updating to state
  explicitly that rolling-hash chunking is reserved, not implemented,
  behind this port — done as part of this phase's documentation
  updates.

## Rejected: size-only `ChunkingStrategy` (`chunk_size_for(remaining_bytes) -> int`)

Simpler to read and to implement for `FixedSizeChunkingStrategy` alone,
but structurally incapable of expressing content-defined chunking,
which must inspect actual byte content to choose a cut point. Adopting
it now would have meant a breaking port change in whichever future
phase implements rolling-hash chunking — precisely the kind of
API instability Phase 2's architecture regression review was asked to
catch.

## Rejected: implementing `RollingHashChunkingStrategy` now, unused

Phase 2's explicit scope is "chunk engine + SHA-256 hash engine";
shipping an unused content-defined implementation would be
under-scoped work with no caller and no tests exercising it for real,
against the phase's own "do not implement future phases" instruction.
The port is designed to make adding it later cheap; adding it now
would not be cheaper, only earlier.
