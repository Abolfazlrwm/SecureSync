"""Use case: autonomously receive and reconstruct files pushed by peers.

ADR-0025 (Phase 20) disclosed a real gap: `SyncFileUseCase.push` sends
chunks over `TransferTransport.send_chunk`, but nothing on the
receiving side ever turned arriving chunks into a reconstructed file
-- `pull` doesn't have this problem because it uses
`ManifestExchangeTransport.request_chunks`, a genuine request/response
exchange, but a `push` is unsolicited by definition.

`ReceivePushedFilesUseCase` is that missing piece: it runs for the
lifetime of the application, draining
`TransferTransport.receive_pushes()` and writing each arriving chunk
into its correct position in the target file via `FileReconstructor`.
See ``docs/adr/0026-push-receiver.md``.

A push is unsolicited, so *everything* about it is chosen by the
sender and must be treated as hostile input:

* ``relative_path`` is resolved through
  :func:`~securesync.shared.safe_path.resolve_within`, which guarantees
  the write target stays inside the sync root.
* each chunk's bytes are hashed and compared against the digest the
  sender declared before anything is written, so a peer cannot store
  content that does not match the hash it promised.
* ``offset``, ``size`` and ``total_chunks`` are bounded, so a peer
  cannot make this device allocate an arbitrarily large sparse file or
  hold an unbounded per-file bookkeeping structure.
* bytes accumulate in a temporary file that is renamed into place only
  once every expected chunk has arrived, so an interrupted transfer
  never leaves a truncated file at a name that looks complete.
* a chunk that fails any of the above is dropped and logged; it never
  ends the loop, which would let any peer deny receipt to all others.

See ``docs/adr/0027-security-audit-and-hardening.md``.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import structlog

from securesync.domain.chunking import ChunkHasher
from securesync.domain.conflict import VersionVector
from securesync.domain.metadata import FileMetadata, MetadataRepository
from securesync.domain.reconstruction import FileReconstructor
from securesync.domain.transfer import IncomingPush, TransferTransport
from securesync.shared.exceptions import ChunkEngineError, SecureSyncError
from securesync.shared.safe_path import UnsafePathError, resolve_within

logger = structlog.get_logger(__name__)

_MIB: Final = 1024 * 1024


class PushRejectedError(SecureSyncError, ValueError):
    """Raised when an arriving push is malformed, unverifiable, or out of bounds."""


@dataclass(frozen=True, slots=True)
class PushLimits:
    """Resource ceilings applied to every arriving push.

    Every field bounds something a peer otherwise controls. Defaults are
    sized for ordinary use (4 MiB chunks, files far below 64 GiB) and
    are deliberately generous; they exist to stop unbounded allocation,
    not to be tight.

    Attributes:
        max_chunk_size: Largest accepted ``size`` for one chunk. A
            chunk's bytes are held in memory while being verified, so
            this is the per-message memory ceiling.
        max_file_size: Largest accepted ``offset + size``. Bounds how
            far a peer can make a file grow with sparse writes.
        max_total_chunks: Largest accepted ``total_chunks``. Bounds the
            per-file bookkeeping a peer can force.
        max_pending_files: How many files may be partially assembled at
            once. Bounds total temporary-file usage across files.
        partial_timeout_seconds: How long a partially assembled file may
            sit without progress before its temporary file is discarded.
        sweep_interval_seconds: How often expired partial files are swept.
    """

    max_chunk_size: int = 64 * _MIB
    max_file_size: int = 64 * 1024 * _MIB
    max_total_chunks: int = 100_000
    max_pending_files: int = 64
    partial_timeout_seconds: float = 300.0
    sweep_interval_seconds: float = 30.0


@dataclass
class _PendingFile:
    """Assembly state for one file's in-flight push.

    Attributes:
        partial: The temporary file bytes are written into, renamed to
            the real path only once the file is complete.
        received_indices: Chunk indices seen so far. A set rather than
            a counter so a resent (duplicate) chunk cannot make the
            receiver believe it has more chunks than it does and commit
            a file with a hole in it.
        version_vector: Merged sender version vectors, if any arrived.
        last_activity: ``time.monotonic()`` of the last accepted chunk,
            used to expire abandoned transfers.
    """

    partial: Path
    received_indices: set[int] = field(default_factory=set)
    version_vector: VersionVector | None = None
    last_activity: float = field(default_factory=time.monotonic)


class ReceivePushedFilesUseCase:
    """Drains unsolicited pushes and reconstructs each file as it completes.

    Stateful across the lifetime of `run_forever`: tracks, per
    relative_path, how many of the expected chunks have arrived so far
    (`_pending`), since a push's chunks can interleave with another
    file's if two peers push concurrently. A relative_path is
    considered complete — and its `FileMetadata` is saved — once
    every chunk the sender declared has arrived and been verified.
    """

    def __init__(
        self,
        transport: TransferTransport,
        sync_root: Path,
        file_reconstructor: FileReconstructor,
        metadata_repo: MetadataRepository,
        own_device_id: str,
        hasher: ChunkHasher,
        limits: PushLimits | None = None,
    ) -> None:
        """Initialize the use case.

        Args:
            transport: Drained via `receive_pushes()` for incoming chunks.
            sync_root: This device's sync directory — chunks are
                reconstructed at `sync_root / relative_path`, after
                that path is validated to stay inside `sync_root`
                (see `shared.safe_path`).
            file_reconstructor: Writes each chunk at its byte offset
                within the target file, and owns the temporary-file
                lifecycle that makes a completed push appear atomically.
            metadata_repo: Updated with a new `FileMetadata` once a
                file's chunks have all arrived.
            own_device_id: Used to build a fallback version vector
                when the sender didn't provide one (legacy senders,
                per ADR-0024's existing fallback pattern).
            hasher: Computes each chunk's digest so the received bytes
                can be checked against the digest the sender declared.
            limits: Resource ceilings for arriving pushes. Defaults to
                :class:`PushLimits`.
        """
        self._transport = transport
        self._sync_root = sync_root
        self._file_reconstructor = file_reconstructor
        self._metadata_repo = metadata_repo
        self._own_device_id = own_device_id
        self._hasher = hasher
        self._limits = limits or PushLimits()
        self._pending: dict[str, _PendingFile] = {}

    async def run_forever(self) -> None:
        """Drain incoming pushes and reconstruct each file as it completes.

        Runs until the surrounding task is cancelled (the normal way
        every background loop in this application is stopped — see
        `main.py`'s `bootstrap`). Never returns on its own.

        A single malformed or hostile message is logged and dropped; it
        never ends the loop. Everything arriving here is peer-supplied,
        so letting one bad message raise would hand any peer a
        permanent denial of service against this device's ability to
        receive from *all* peers.

        On cancellation, every partially assembled file is discarded:
        nothing half-written is left behind for the next run to
        mistake for real content.
        """
        sweeper = asyncio.create_task(self._sweep_expired_partials())
        try:
            async for incoming in self._transport.receive_pushes():
                try:
                    await self._handle_push(incoming)
                except (
                    UnsafePathError,
                    PushRejectedError,
                    ChunkEngineError,
                    OSError,
                    ValueError,
                    KeyError,
                ) as exc:
                    logger.warning(
                        "push_rejected",
                        relative_path=incoming.relative_path,
                        error=str(exc),
                        error_type=type(exc).__name__,
                    )
        finally:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper
            self._abort_all_partials()

    async def _handle_push(self, incoming: IncomingPush) -> None:
        """Verify one arriving chunk, write it, and finalize its file when complete.

        Raises:
            UnsafePathError: If `incoming.relative_path` would resolve
                outside the sync root. Raised before anything is written.
            PushRejectedError: If the chunk is out of bounds or its
                bytes don't match its declared digest. Raised before
                anything is written.
        """
        # The one place a peer-supplied name becomes a local path.
        # Validated rather than joined: `sync_root / relative_path`
        # alone lets a peer choose any writable location on this
        # machine (see `shared.safe_path`).
        destination = resolve_within(self._sync_root, incoming.relative_path)
        self._validate(incoming)

        pending = self._pending.get(incoming.relative_path)
        if pending is None:
            if len(self._pending) >= self._limits.max_pending_files:
                raise PushRejectedError(
                    f"too many files partially received ({len(self._pending)}); "
                    "refusing to start another"
                )
            pending = _PendingFile(partial=self._file_reconstructor.begin_partial(destination))
            self._pending[incoming.relative_path] = pending

        pending.last_activity = time.monotonic()
        self._file_reconstructor.write_chunk_at_offset(pending.partial, incoming.chunk)
        pending.received_indices.add(incoming.chunk.metadata.index)
        if incoming.version_vector is not None:
            pending.version_vector = (
                incoming.version_vector
                if pending.version_vector is None
                else pending.version_vector.merge(incoming.version_vector)
            )

        logger.debug(
            "push_chunk_received",
            relative_path=incoming.relative_path,
            progress=f"{len(pending.received_indices)}/{incoming.total_chunks}",
        )

        if len(pending.received_indices) >= incoming.total_chunks:
            await self._finalize(incoming.relative_path, destination, pending)

    def _validate(self, incoming: IncomingPush) -> None:
        """Reject a push that is out of bounds or whose bytes don't match its digest.

        The digest check is the one that matters most: without it the
        declared ``chunk_hash`` is decoration, and a peer can store
        whatever bytes it likes while the manifest other peers fetch
        describes something else entirely.

        Raises:
            PushRejectedError: If any bound is exceeded or the digest
                doesn't match.
        """
        metadata = incoming.chunk.metadata

        if incoming.total_chunks < 1:
            raise PushRejectedError(f"total_chunks must be >= 1, got {incoming.total_chunks}")
        if incoming.total_chunks > self._limits.max_total_chunks:
            raise PushRejectedError(
                f"total_chunks {incoming.total_chunks} exceeds limit "
                f"{self._limits.max_total_chunks}"
            )
        if metadata.size > self._limits.max_chunk_size:
            raise PushRejectedError(
                f"chunk size {metadata.size} exceeds limit {self._limits.max_chunk_size}"
            )
        if metadata.offset + metadata.size > self._limits.max_file_size:
            raise PushRejectedError(
                f"chunk at offset {metadata.offset} would grow the file past "
                f"{self._limits.max_file_size} bytes"
            )

        declared = metadata.chunk_hash
        if declared is None:
            raise PushRejectedError(
                "chunk declares no hash; refusing to store unverifiable content"
            )
        actual = self._hasher.hash(incoming.chunk.data)
        if actual.algorithm != declared.algorithm or actual.digest != declared.digest:
            raise PushRejectedError(
                f"chunk hash mismatch for {incoming.relative_path!r}: "
                f"declared {declared}, computed {actual}"
            )

    async def _finalize(self, relative_path: str, destination: Path, pending: _PendingFile) -> None:
        """Commit the assembled file atomically, then record its metadata."""
        self._file_reconstructor.commit_partial(destination, pending.partial)
        self._pending.pop(relative_path, None)

        existing = await self._metadata_repo.get_file_metadata(relative_path)
        version = pending.version_vector
        if version is None:
            # No version vector arrived with any chunk (legacy sender)
            # -- fall back to bumping our own counter, the same
            # fallback ADR-0024 already established for this exact
            # situation.
            base = existing.version_vector if existing is not None else VersionVector()
            version = base.increment(self._own_device_id)
        elif existing is not None:
            version = version.merge(existing.version_vector)

        await self._metadata_repo.save_file_metadata(
            FileMetadata(
                file_path=relative_path,
                version_vector=version,
                last_modified=datetime.now(UTC),
            )
        )
        logger.info("push_received_and_reconstructed", relative_path=relative_path)

    async def _sweep_expired_partials(self) -> None:
        """Periodically discard partial files whose transfer has stalled."""
        while True:
            await asyncio.sleep(self._limits.sweep_interval_seconds)
            self._abort_expired_partials()

    def _abort_expired_partials(self) -> None:
        """Discard every partial file that has seen no progress within the timeout."""
        now = time.monotonic()
        expired = [
            relative_path
            for relative_path, pending in self._pending.items()
            if now - pending.last_activity > self._limits.partial_timeout_seconds
        ]
        for relative_path in expired:
            pending = self._pending.pop(relative_path)
            self._file_reconstructor.abort_partial(pending.partial)
            logger.warning(
                "partial_push_timed_out",
                relative_path=relative_path,
                chunks_received=len(pending.received_indices),
            )

    def _abort_all_partials(self) -> None:
        """Discard every in-flight partial file (shutdown path)."""
        for relative_path, pending in self._pending.items():
            self._file_reconstructor.abort_partial(pending.partial)
            logger.warning(
                "partial_push_abandoned",
                relative_path=relative_path,
                chunks_received=len(pending.received_indices),
            )
        self._pending.clear()
