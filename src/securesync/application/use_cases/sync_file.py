"""Use case: synchronize one file with a peer, in an explicit direction.

Composes every piece built across Phases 3-14 into the first genuine
end-to-end file sync: request the peer's manifest, diff it against
the local one, and transfer whichever chunks are missing.

`push` and `pull` are deliberately separate, explicit-direction
methods rather than one method that tries to reconcile both
directions automatically. A pure hash-set diff cannot tell "I have
new content the peer needs" apart from "I have stale content the peer
has already moved past" — both look identical to
:class:`~securesync.domain.delta.DeltaCalculator`, which has no
timestamp or version information to break the tie. Verified in this
session: an automatic-bidirectional first version of this use case
produced exactly that corruption (a device's fresh local edit
overwritten by a peer's stale copy of the same chunk). Requiring the
caller to say which direction it means removes the ambiguity
entirely; deciding *which* direction is correct for a given file is
real conflict resolution, deliberately out of scope here — see
``docs/adr/0022-file-synchronization-use-case.md``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from pathlib import Path

import structlog

from securesync.application.use_cases.calculate_chunk_hashes import CalculateChunkHashesUseCase
from securesync.application.use_cases.chunk_file import ChunkFileUseCase
from securesync.application.use_cases.transfer_chunks import UploadChunksUseCase
from securesync.domain.chunk import Chunk, ChunkCollection
from securesync.domain.chunk_exceptions import ChunkSourceNotFoundError
from securesync.domain.chunking import ChunkingStrategy, ChunkRepository
from securesync.domain.delta import DeltaCalculator
from securesync.domain.manifest_exchange import ManifestExchangeTransport
from securesync.domain.networking import Peer
from securesync.domain.reconstruction import FileReconstructor

logger = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class SyncFileResult:
    """The outcome of a `push` or `pull` sync with a peer.

    Attributes:
        transferred_count: How many chunks were sent or received.
    """

    transferred_count: int


class SyncFileUseCase:
    """Synchronizes one file's content with a peer, in one explicit direction at a time."""

    def __init__(
        self,
        manifest_exchange: ManifestExchangeTransport,
        chunk_file_use_case: ChunkFileUseCase,
        calculate_hashes_use_case: CalculateChunkHashesUseCase,
        upload_use_case: UploadChunksUseCase,
        chunk_repository: ChunkRepository,
        file_reconstructor: FileReconstructor,
    ) -> None:
        """Initialize the use case.

        Args:
            manifest_exchange: Requests the peer's manifest for the
                file, and pulls specific missing chunks' real bytes
                (a genuine request/response — see
                ``docs/adr/0022-file-synchronization-use-case.md`` for
                why this doesn't use
                :class:`~securesync.domain.transfer.TransferTransport`'s
                `request_chunks`, which only waits passively for
                whatever a peer already chose to push).
            chunk_file_use_case: Reads and hashes the local file's
                chunks with their bytes, for whichever ones need uploading.
            calculate_hashes_use_case: Builds the local manifest
                (metadata only) to diff against the peer's.
            upload_use_case: Sends chunks the peer is missing.
            chunk_repository: Where the resulting local manifest is
                saved as the new baseline once sync completes.
            file_reconstructor: Writes downloaded chunks into the
                local file at their correct offset.
        """
        self._manifest_exchange = manifest_exchange
        self._chunk_file_use_case = chunk_file_use_case
        self._calculate_hashes_use_case = calculate_hashes_use_case
        self._upload_use_case = upload_use_case
        self._chunk_repository = chunk_repository
        self._file_reconstructor = file_reconstructor
        self._calculator = DeltaCalculator()

    async def push(
        self,
        peer: Peer,
        sync_root: Path,
        relative_path: str,
        strategy: ChunkingStrategy,
        *,
        chunk_size: int,
    ) -> SyncFileResult:
        """Send `peer` every chunk of `relative_path` it doesn't already have.

        Never modifies the local file — this direction only sends,
        never receives.

        Args:
            peer: The peer to push to.
            sync_root: This device's local sync directory —
                `sync_root / relative_path` is the file read from.
            relative_path: The file to push, as a path relative to
                each side's own sync root (see the module docstring
                and ``docs/adr/0022-file-synchronization-use-case.md``
                for why never an absolute path).
            strategy: Decides where each chunk boundary falls.
            chunk_size: Recorded on the manifest built for this push.

        Returns:
            A `SyncFileResult` with how many chunks were sent.

        Raises:
            ChunkSourceNotFoundError: If the local file doesn't exist.
            ChunkSourceAccessError: If the local file can't be read.
        """
        source_path = sync_root / relative_path
        current = await self._calculate_hashes_use_case.build_manifest(
            source_path, strategy, chunk_size=chunk_size
        )
        peer_manifest = await self._normalized_peer_manifest(peer, relative_path, source_path)

        upload_plan = self._calculator.compute(baseline=peer_manifest, current=current)
        if upload_plan.transfer_count > 0:
            needed_hashes = {
                metadata.chunk_hash.digest
                for metadata in upload_plan.chunks_to_transfer
                if metadata.chunk_hash is not None
            }
            await self._upload_use_case.execute(
                peer, self._filter_chunks_to_upload(source_path, strategy, needed_hashes)
            )
        await asyncio.to_thread(self._chunk_repository.save, current)

        logger.info(
            "file_pushed",
            peer_id=peer.device_id,
            relative_path=relative_path,
            transferred_count=upload_plan.transfer_count,
        )
        return SyncFileResult(transferred_count=upload_plan.transfer_count)

    async def pull(
        self,
        peer: Peer,
        sync_root: Path,
        relative_path: str,
        strategy: ChunkingStrategy,
        *,
        chunk_size: int,
    ) -> SyncFileResult:
        """Fetch from `peer` every chunk of `relative_path` missing locally.

        Never sends anything to the peer — this direction only
        receives, never pushes.

        Args:
            peer: The peer to pull from.
            sync_root: This device's local sync directory —
                `sync_root / relative_path` is the file written to.
            relative_path: The file to pull, as a path relative to
                each side's own sync root.
            strategy: Decides where each chunk boundary falls.
            chunk_size: Recorded on manifests built during this pull.

        Returns:
            A `SyncFileResult` with how many chunks were received. Zero
            if the peer doesn't have this file at all.
        """
        source_path = sync_root / relative_path
        current = await self._local_manifest_or_empty(source_path, strategy, chunk_size)
        peer_manifest = await self._normalized_peer_manifest(peer, relative_path, source_path)
        if peer_manifest is None:
            return SyncFileResult(transferred_count=0)

        download_plan = self._calculator.compute(baseline=current, current=peer_manifest)
        transferred_count = 0
        if download_plan.transfer_count > 0:
            hashes = [
                metadata.chunk_hash.digest
                for metadata in download_plan.chunks_to_transfer
                if metadata.chunk_hash is not None
            ]
            async for chunk in self._manifest_exchange.request_chunks(
                peer, relative_path, hashes
            ):
                await asyncio.to_thread(
                    self._file_reconstructor.write_chunk_at_offset, source_path, chunk
                )
                transferred_count += 1

        final_manifest = (
            await self._calculate_hashes_use_case.build_manifest(
                source_path, strategy, chunk_size=chunk_size
            )
            if transferred_count
            else current
        )
        await asyncio.to_thread(self._chunk_repository.save, final_manifest)

        logger.info(
            "file_pulled",
            peer_id=peer.device_id,
            relative_path=relative_path,
            transferred_count=transferred_count,
        )
        return SyncFileResult(transferred_count=transferred_count)

    async def _local_manifest_or_empty(
        self, source_path: Path, strategy: ChunkingStrategy, chunk_size: int
    ) -> ChunkCollection:
        """Build the local manifest, or an empty one if `source_path` doesn't exist yet.

        A file being pulled for the first time (the peer has it, this
        device doesn't) has nothing local to build a manifest from —
        that's a normal starting state, not an error, so it's treated
        as "zero chunks" rather than propagating `ChunkSourceNotFoundError`.
        """
        try:
            return await self._calculate_hashes_use_case.build_manifest(
                source_path, strategy, chunk_size=chunk_size
            )
        except ChunkSourceNotFoundError:
            return ChunkCollection(
                source_path=source_path, chunk_size=chunk_size, total_size=0, chunks=()
            )

    async def _normalized_peer_manifest(
        self, peer: Peer, relative_path: str, source_path: Path
    ) -> ChunkCollection | None:
        """Request the peer's manifest, with its path normalized to this device's own.

        `DeltaCalculator` requires `baseline.source_path == current.source_path`
        (a same-local-file invariant from its Phase 3 design — see
        ADR-0009). The peer's manifest carries *its own* absolute
        path, which is legitimately different from this device's for
        the same logical file (ADR-0022), so it's normalized here
        rather than relaxing that invariant in `DeltaCalculator`
        itself, which is still correct for its original, purely-local use.
        """
        peer_manifest = await self._manifest_exchange.request_manifest(peer, relative_path)
        if peer_manifest is None:
            return None
        return replace(peer_manifest, source_path=source_path)

    async def _filter_chunks_to_upload(
        self, source_path: Path, strategy: ChunkingStrategy, needed_hashes: set[str]
    ) -> AsyncIterator[Chunk]:
        """Stream the local file's chunks, yielding only the ones the peer needs."""
        async for chunk in self._chunk_file_use_case.execute(source_path, strategy):
            chunk_hash = chunk.metadata.chunk_hash
            if chunk_hash is not None and chunk_hash.digest in needed_hashes:
                yield chunk
