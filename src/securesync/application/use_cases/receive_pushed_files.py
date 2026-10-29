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

Because a push is unsolicited, its `relative_path` is chosen entirely
by the sender and must be treated as hostile input: it is resolved
through :func:`~securesync.shared.safe_path.resolve_within`, which
guarantees the write target stays inside the sync root. See
``docs/adr/0027-security-audit-and-hardening.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import structlog

from securesync.domain.conflict import VersionVector
from securesync.domain.metadata import FileMetadata, MetadataRepository
from securesync.domain.reconstruction import FileReconstructor
from securesync.domain.transfer import IncomingPush, TransferTransport
from securesync.shared.exceptions import ChunkEngineError
from securesync.shared.safe_path import UnsafePathError, resolve_within

logger = structlog.get_logger(__name__)


@dataclass
class _PendingFile:
    """How many of a file's incoming chunks we've written so far."""

    chunks_written: int = 0
    version_vector: VersionVector | None = None


class ReceivePushedFilesUseCase:
    """Drains unsolicited pushes and reconstructs each file as it completes.

    Stateful across the lifetime of `run_forever`: tracks, per
    relative_path, how many of the expected chunks have arrived so far
    (`_pending`), since a push's chunks can interleave with another
    file's if two peers push concurrently. A relative_path is
    considered complete — and its `FileMetadata` is saved — once
    `chunks_written` reaches the `total_chunks` the sender declared.
    """

    def __init__(
        self,
        transport: TransferTransport,
        sync_root: Path,
        file_reconstructor: FileReconstructor,
        metadata_repo: MetadataRepository,
        own_device_id: str,
    ) -> None:
        """Initialize the use case.

        Args:
            transport: Drained via `receive_pushes()` for incoming chunks.
            sync_root: This device's sync directory — chunks are
                reconstructed at `sync_root / relative_path`, after
                that path is validated to stay inside `sync_root`
                (see `shared.safe_path`).
            file_reconstructor: Writes each chunk at its byte offset
                within the target file.
            metadata_repo: Updated with a new `FileMetadata` once a
                file's chunks have all arrived.
            own_device_id: Used to build a fallback version vector
                when the sender didn't provide one (legacy senders,
                per ADR-0024's existing fallback pattern).
        """
        self._transport = transport
        self._sync_root = sync_root
        self._file_reconstructor = file_reconstructor
        self._metadata_repo = metadata_repo
        self._own_device_id = own_device_id
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
        """
        async for incoming in self._transport.receive_pushes():
            try:
                await self._handle_push(incoming)
            except (UnsafePathError, ChunkEngineError, OSError, ValueError, KeyError) as exc:
                logger.warning(
                    "push_rejected",
                    relative_path=incoming.relative_path,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )

    async def _handle_push(self, incoming: IncomingPush) -> None:
        """Write one arriving chunk and finalize its file once all chunks are in.

        Raises:
            UnsafePathError: If `incoming.relative_path` would resolve
                outside the sync root. Raised before anything is
                written.
        """
        # The one place a peer-supplied name becomes a local path.
        # Validated rather than joined: `sync_root / relative_path`
        # alone lets a peer choose any writable location on this
        # machine (see `shared.safe_path`).
        destination = resolve_within(self._sync_root, incoming.relative_path)
        self._file_reconstructor.write_chunk_at_offset(destination, incoming.chunk)

        pending = self._pending.setdefault(incoming.relative_path, _PendingFile())
        pending.chunks_written += 1
        if incoming.version_vector is not None:
            pending.version_vector = (
                incoming.version_vector
                if pending.version_vector is None
                else pending.version_vector.merge(incoming.version_vector)
            )

        logger.debug(
            "push_chunk_received",
            relative_path=incoming.relative_path,
            progress=f"{pending.chunks_written}/{incoming.total_chunks}",
        )

        if pending.chunks_written >= incoming.total_chunks:
            await self._finalize(incoming.relative_path, pending)

    async def _finalize(self, relative_path: str, pending: _PendingFile) -> None:
        """Record the now-complete file's metadata and forget its progress."""
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
        del self._pending[relative_path]
        logger.info("push_received_and_reconstructed", relative_path=relative_path)
