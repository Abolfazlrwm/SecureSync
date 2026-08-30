# ADR 0026: Push Receiver

**Status:** Accepted
**Date:** Phase 21

## Context

ADR-0025 (Phase 20) disclosed a real, deliberately unfixed gap: a
`push` (ADR-0023/0024) really did deliver an encrypted chunk to a
peer's real listening socket once Phase 20's three bugs were fixed,
but nothing on the receiving side ever turned that arriving chunk into
a reconstructed file. `pull` doesn't have this problem — it uses
`ManifestExchangeTransport.request_chunks`, a genuine request/response
RPC where the requester already knows exactly what it's asking for.
`push` is unsolicited by nature: nothing tells the receiver in advance
that anything is coming.

Building this receiver surfaced a second, more fundamental gap before
any code could be written for it: **the wire payload for a pushed
chunk carried no file identity at all.** `send_chunk`'s payload had
`chunk_id`, `index`, `size`, `offset`, `hash_algorithm`, `hash_digest`,
and `data` — nothing saying which file, or how many chunks make up the
complete transfer. A receiver had no way to know where to write an
arriving chunk, or when a file was done, purely from the chunk itself.

## Decision

### 1. Extend the wire protocol: `relative_path`, `total_chunks`, `version_counters`

`TransferTransport.send_chunk` (both `TcpTransferTransport` and
`InProcessTransferTransport`) now takes `relative_path: str`,
`total_chunks: int`, and an optional `version_vector: VersionVector |
None`, and includes them in the payload. `relative_path` is always
relative to both peers' sync roots, matching every other cross-peer
identifier in this codebase (ADR-0022's reasoning for why an absolute
path can't be used applies identically here). `total_chunks` is the
number of chunks in *this specific push* — for an incremental update
where only some chunks changed, this is the count of retransmitted
chunks, not the file's full chunk count, since the receiving side's
existing file already has correct bytes everywhere else.

### 2. `TransferTransport.receive_pushes()` — a new abstract method

Drains whatever arrives unconditionally, yielding an `IncomingPush`
(`relative_path`, `total_chunks`, `chunk`, `version_vector`) for each.
Unlike `request_chunks`, this doesn't know in advance which peer a
message came from. `TcpTransferTransport`'s implementation resolves
this by trying every currently known session's `receive_key` in turn
— AEAD authentication naturally rejects the wrong key, so this both
decrypts and identifies the sender in one step, which is practical for
the small peer counts a P2P sync tool actually has.
`SessionKeyStore.all_sessions()` was added to support this.

### 3. `ReceivePushedFilesUseCase` — the actual receiver

A new use case that runs for the application's lifetime (wired into
`bootstrap()` as a background task, alongside the existing
`_drain_inbound_handshakes` loop): drains `receive_pushes()`, writes
each chunk at its offset via `FileReconstructor`, and once a
`relative_path`'s `chunks_written` reaches its declared
`total_chunks`, saves a new `FileMetadata` — merging the sender's
version vector with any existing local one (`VersionVector.merge`),
or falling back to bumping this device's own counter when no version
arrived (a legacy/no-version sender, matching ADR-0024's existing
fallback pattern for exactly this situation).

### 4. `main.py` also gained a proper `local_version_provider`

Wiring this phase's end-to-end test (below) surfaced a related, small
gap: `SyncFileUseCase` was never given a `local_version_provider`, so
every real push transmitted `version_vector=None` regardless of what
the sender actually knew. `main.py` now supplies one backed by
`metadata_repo.get_file_metadata`, so a real push carries a real
version vector end to end. `LocalVersionProvider` in `sync_file.py`
was also fixed to actually be a `Protocol` (it was a plain class,
which meant mypy rejected any ordinary function passed for this
parameter even though the runtime behavior always worked).

## Consequences

`tests/integration/test_end_to_end_sync.py` (Phase 20) was rewritten
to remove its manual `DownloadChunksUseCase` workaround entirely — it
now just writes a file on one real instance and polls for it to
appear on the other, the way a person actually using SecureSync would
experience it. The rewrite itself caught a race: the old workaround's
direct `request_chunks` call and the new background receiver's
`receive_pushes` loop both drain the same inbox, and the workaround
lost that race and hung. Removing the workaround was the correct fix,
not a bug in the receiver — confirmation that a genuinely-fixed gap
tends to make its own old tests obsolete.

This closes the last disclosed gap from ADR-0025: cross-device sync
(discovery → handshake → direction resolution → transfer →
reconstruction) is now fully autonomous, in both directions, over a
real network, with no operator or test intervention required.
