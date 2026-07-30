# ADR 0010: Persistent Manifest Storage Is Already `ChunkRepository` / `FileChunkRepository`

**Status:** Accepted
**Date:** Post-Phase-3 reconciliation

## Context

A task brief arrived describing a "Phase 4 — Persistent Manifest
Repository": a versioned, atomic, JSON-on-disk store for a file's
chunk manifest, with a `JsonManifestRepository` infrastructure adapter
and four new application use cases (`SaveManifestUseCase`,
`LoadManifestUseCase`, `DeleteManifestUseCase`,
`ManifestExistsUseCase`).

Two things about that brief don't hold up against this repository's
actual state, verified directly rather than taken on trust:

1. **It isn't the project's real Phase 4.** `ROADMAP.md` (updated at
   the end of Phase 3, before this brief arrived) defines Phase 4 as
   **Peer Discovery** (UDP broadcast, mDNS, peer cache, heartbeat,
   reconnect). The persistent-metadata-store work the brief describes
   already has a place on the roadmap — **Phase 8, Metadata
   Database** — and `FileChunkRepository`'s own module docstring,
   written back in Phase 2, already says as much: *"A placeholder
   until the SQLite-backed metadata store planned for Phase 8 lands."*
2. **The functionality it asks for already exists.** `ChunkRepository`
   (`domain/chunking.py`, Phase 2) is exactly "a manifest represents
   the state of one file after chunking; contains only metadata,
   never chunk bytes; one manifest per file" — that's `ChunkCollection`
   verbatim, described by the port's own docstring. Its Phase 2
   implementation, `FileChunkRepository`
   (`infrastructure/chunking/file_chunk_repository.py`), already
   provides, verified against its actual code and its existing test
   suite (`tests/unit/infrastructure/chunking/test_file_chunk_repository.py`)
   rather than assumed from its docstring:
   - **One JSON document per file** (`save`/`load` keyed by source path).
   - **Atomic, crash-safe writes** — `atomic_write_bytes` (write to a
     temp file, `os.replace`, `contextlib.suppress(OSError)` around
     best-effort temp-file cleanup so a cleanup failure never masks
     the real error) — `test_save_failure_raises_chunk_engine_error`
     and the `_atomic_write.py` implementation itself confirm this;
     no test or code path leaves a partial manifest visible to a
     concurrent `load`.
   - **OS-safe, deterministic naming** — `sha256(resolved_path).hexdigest() + ".json"`,
     never the raw filename — fixed-length, ASCII-only, valid on
     Windows/Linux/macOS, confirmed by
     `test_relative_and_absolute_paths_to_same_file_share_a_manifest`.
   - **UTF-8-safe for any source path**, including non-ASCII
     (Unicode) paths — the path string is UTF-8-encoded before
     hashing, so the resulting digest is unaffected by which
     characters the original path contained.
   - **Meaningful rejection of corrupted or incomplete manifests** —
     `test_corrupted_json_raises_chunk_engine_error` and
     `test_manifest_missing_required_field_raises_chunk_engine_error`
     both confirm `ChunkEngineError` (a domain-meaningful type, not a
     bare `RuntimeError` or an uncaught parser exception) is raised
     for malformed JSON and for structurally incomplete payloads.

Re-implementing this under a new name (`JsonManifestRepository`) with
parallel use cases would directly contradict ADR-0009, which already
examined — and rejected — introducing a second cache/port alongside
`ChunkRepository` for exactly this reason: duplication without a
behavioral difference.

## Decision

**No new component is introduced.** `ChunkRepository` /
`FileChunkRepository` *is* the project's persistent manifest
repository. No `JsonManifestRepository`, and no
`SaveManifestUseCase` / `LoadManifestUseCase` / `DeleteManifestUseCase` /
`ManifestExistsUseCase` are added — `ChunkRepository.save` /
`.load` already cover the save/load half of that surface directly,
and a `delete`/`exists` capability is deferred until a concrete use
case actually needs one (see Consequences).

**`ROADMAP.md` is reconciled, not renumbered.** A new entry, **Phase
3.5 — Persistent Manifest Repository (retroactive)**, is inserted
between Phase 3 and Phase 4 to record that this capability was
already delivered — as part of Phase 2's `ChunkRepository` port and
Phase 3's reuse of it as the delta-sync chunk cache — rather than
silently absorbing it into the Phase 3 entry after the fact. Phase 4
(Peer Discovery) and every later phase keep their existing numbers
unchanged; nothing about the roadmap's substance changes, only this
gap in what it documented.

**The audit found no genuine defect to fix.** Every substantive
requirement in the brief (schema is metadata-only and never stores
chunk bytes, one manifest per file, atomic write, crash safety,
OS-safe naming, meaningful rejection of corrupted input) was checked
directly against `file_chunk_repository.py` and its test suite and
already holds. `FileChunkRepository` is therefore left byte-for-byte
unchanged by this reconciliation.

## Consequences

**Positive**

- Zero duplicated code, zero duplicated port, zero contradiction of
  ADR-0009's DRY/YAGNI reasoning.
- The roadmap gap is now recorded truthfully instead of silently
  reinterpreting Phase 3's scope after the fact — future readers of
  `ROADMAP.md`/`CHANGELOG.md` see exactly when persistent manifest
  storage actually arrived (Phase 2) versus when it was formally
  documented as its own milestone (this reconciliation).
- `FileChunkRepository` remains exactly what Phase 2's tests already
  verify; no risk was introduced by editing already-production code
  without a concrete bug driving the change.

**Negative / trade-offs accepted**

- No explicit JSON schema `"version"` field exists on the manifest
  format today. This was considered and deliberately not added here:
  the port's own docstring already commits to *replacing* this
  adapter wholesale at Phase 8 (a JSON file store becoming a SQLite
  database), not evolving the JSON schema in place — so an in-place
  version field would guard against a migration path this project
  isn't taking. If Phase 8 changes course and needs to read
  Phase-2-era JSON manifests during a transition, that migration can
  inspect the (already fully typed) JSON structurally; version
  negotiation logic can be added then, against a concrete real need,
  rather than speculatively now.
- No `delete`/`exists` operation exists on `ChunkRepository` yet.
  Nothing in the codebase currently needs to delete a manifest or
  check for one's existence without loading it (`load` returning
  `None` already serves every current "does a baseline exist" check
  — see `ComputeDeltaUseCase`). Adding them now, with no caller,
  would be exactly the speculative-port-surface problem ADR-0009's
  "Rejected" section warns against. A concrete future need (e.g. a
  "forget this file" user-facing operation) should add `delete` to
  the `ChunkRepository` port — extending the existing one, still not
  a new component — at the point that need is real.
- The manifest JSON is compact (`orjson.dumps` with no indent option),
  not pretty-printed. This was a Phase 2 design choice for a
  machine-only artifact no one is expected to hand-edit, made before
  this brief and unrelated to it; changing it now, with no bug behind
  it, would be an unrequested behavior change to already-shipped code
  and was left alone.

## Rejected: implement the brief as written (`JsonManifestRepository` + 4 new use cases)

Would satisfy the brief's literal text but duplicate
`ChunkRepository`/`FileChunkRepository` under new names for no
behavioral difference — the same DRY/YAGNI violation ADR-0009 already
rejected once. Also wrong on process grounds: it would silently
treat an external brief's phase numbering as authoritative over this
repository's own `ROADMAP.md`, which is exactly the "never trust
documentation, verify everything yourself" failure mode this project's
own working process exists to catch.

## Rejected: fold this reconciliation silently into the existing Phase 3 entry

Editing the Phase 3 `ROADMAP.md`/`CHANGELOG.md` entries after the fact
to retroactively claim they always covered "persistent manifest
storage" would erase the fact that this was a separate, later
clarification — making the project history less honest about *when*
each capability was actually established and reviewed.
