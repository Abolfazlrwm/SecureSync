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
entirely.

Phase 17: `sync` is a higher-level method that consults
:class:`~securesync.domain.sync_direction.SyncDirectionResolver` and
then dispatches to `push` / `pull` / `noop` / `conflict` handling
automatically — using the `VersionVector` the peer's manifest
response now carries. Conflict falls back to
:class:`~securesync.application.use_cases.conflict_resolution.LastWriterWinsStrategy`
rather than crashing. See
``docs/adr/0024-version-aware-sync-direction.md``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

import structlog

from securesync.application.use_cases.calculate_chunk_hashes import CalculateChunkHashesUseCase
from securesync.application.use_cases.chunk_file import ChunkFileUseCase
from securesync.application.use_cases.conflict_resolution import LastWriterWinsStrategy
from securesync.application.use_cases.transfer_chunks import UploadChunksUseCase
from securesync.domain.chunk import Chunk, ChunkCollection
from securesync.domain.chunk_exceptions import ChunkSourceNotFoundError
from securesync.domain.chunking import ChunkingStrategy, ChunkRepository
from securesync.domain.conflict import MergeStrategy, VersionVector
from securesync.domain.delta import DeltaCalculator
from securesync.domain.manifest_exchange import (
    ManifestExchangeTransport,
    ManifestWithVersion,
)
from securesync.domain.networking import Peer
from securesync.domain.reconstruction import FileReconstructor
from securesync.domain.sync_direction import (
    SyncDirection,
    SyncDirectionDecision,
    SyncDirectionResolver,
)

logger = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class SyncFileResult:
    """The outcome of a `push`, `pull`, or `sync` with a peer.

    Attributes:
        transferred_count: How many chunks were sent or received.
        direction: The direction actually taken (push/pull/noop).
            ``None`` for the explicit `push`/`pull` methods, which
            don't make a direction decision.
    """

    transferred_count: int
    direction: str | None = None


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
        local_version_provider: LocalVersionProvider | None = None,
        direction_resolver: SyncDirectionResolver | None = None,
    ) -> None:
        """Initialize the use case.

        Args:
            manifest_exchange: Requests the peer's manifest (and
                `VersionVector`) for the file, and pulls specific
                missing chunks' real bytes (a genuine request/response
                — see ``docs/adr/0022-file-synchronization-use-case.md``
                for why this doesn't use
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
            local_version_provider: Optional callable returning the
                local `VersionVector` for a given relative path. When
                provided, `sync` uses it together with the peer's
                reported version to decide push/pull/conflict.
            direction_resolver: Optional `SyncDirectionResolver`. When
                omitted, a default stateless instance is used (the
                service is pure, so sharing the default is safe).
        """
        self._manifest_exchange = manifest_exchange
        self._chunk_file_use_case = chunk_file_use_case
        self._calculate_hashes_use_case = calculate_hashes_use_case
        self._upload_use_case = upload_use_case
        self._chunk_repository = chunk_repository
        self._file_reconstructor = file_reconstructor
        self._local_version_provider = local_version_provider
        self._direction_resolver = direction_resolver or SyncDirectionResolver()
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
        local_version = (
            await self._local_version_provider(relative_path)
            if self._local_version_provider is not None
            else None
        )

        upload_plan = self._calculator.compute(baseline=peer_manifest, current=current)
        if upload_plan.transfer_count > 0:
            needed_hashes = {
                metadata.chunk_hash.digest
                for metadata in upload_plan.chunks_to_transfer
                if metadata.chunk_hash is not None
            }
            await self._upload_use_case.execute(
                peer,
                self._filter_chunks_to_upload(source_path, strategy, needed_hashes),
                relative_path=relative_path,
                # The count of chunks actually being sent *in this
                # push* (only what upload_plan says the peer is
                # missing), not the file's full chunk count — an
                # incremental update only retransmits the changed
                # chunks, and the receiving side's existing file
                # already has correct bytes everywhere else (see
                # ReceivePushedFilesUseCase / ADR-0026).
                total_chunks=len(needed_hashes),
                version_vector=local_version,
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

    async def sync(
        self,
        peer: Peer,
        sync_root: Path,
        relative_path: str,
        strategy: ChunkingStrategy,
        *,
        chunk_size: int,
        merge_strategy: MergeStrategy | None = None,
    ) -> SyncFileResult:
        """Decide direction, then push / pull / noop / conflict-handle accordingly.

        Phase 17: consults `SyncDirectionResolver` using the local
        + peer `VersionVector` and the two manifests. On CONFLICT,
        falls back to `LastWriterWinsStrategy` (Phase 7) — choosing
        "remote wins" pulls the peer's version; choosing "local
        wins" no-ops. `merge_strategy` lets a caller inject a
        different policy; default is `LastWriterWinsStrategy()`.

        If ``merge_strategy`` is ``None`` a default
        :class:`~securesync.application.use_cases.conflict_resolution.LastWriterWinsStrategy`
        is used automatically (no None-check needed inside the method).

        Args:
            peer: The peer to sync with.
            sync_root: This device's local sync directory.
            relative_path: The file to sync, relative to `sync_root`.
            strategy: Decides where each chunk boundary falls.
            chunk_size: Recorded on manifests built during this sync.
            merge_strategy: Optional pluggable conflict policy. If
                ``None`` (default),
                :class:`~securesync.application.use_cases.conflict_resolution.LastWriterWinsStrategy`
                is used automatically.

        Returns:
            A `SyncFileResult` with `direction` populated (push/pull/noop).
        """
        if merge_strategy is None:
            merge_strategy = LastWriterWinsStrategy()

        source_path = sync_root / relative_path
        local_collection = await self._local_manifest_or_empty(source_path, strategy, chunk_size)
        local_version = (
            await self._local_version_provider(relative_path)
            if self._local_version_provider is not None
            else None
        )

        peer_mv = await self._request_peer_manifest_with_version(peer, relative_path)
        if peer_mv is None:
            # Peer doesn't have it at all — only meaningful if we do.
            if local_collection.chunk_count > 0:
                logger.info(
                    "file_pushed_no_peer_manifest",
                    peer_id=peer.device_id,
                    relative_path=relative_path,
                )
                return await self.push(
                    peer, sync_root, relative_path, strategy, chunk_size=chunk_size
                )
            return SyncFileResult(transferred_count=0, direction=SyncDirection.NOOP.value)

        decision: SyncDirectionDecision = self._direction_resolver.resolve(
            local_collection=local_collection,
            local_version=local_version,
            remote_collection=peer_mv.collection,
            remote_version=peer_mv.version,
        )
        logger.info(
            "sync_direction_resolved",
            peer_id=peer.device_id,
            relative_path=relative_path,
            direction=decision.direction.value,
            reason=decision.reason,
        )

        if decision.direction is SyncDirection.PUSH:
            return await self.push(
                    peer, sync_root, relative_path, strategy, chunk_size=chunk_size
                )
        if decision.direction is SyncDirection.PULL:
            return await self.pull(peer, sync_root, relative_path, strategy, chunk_size=chunk_size)
        if decision.direction is SyncDirection.NOOP:
            return SyncFileResult(transferred_count=0, direction=SyncDirection.NOOP.value)

        # CONFLICT — defer to the merge strategy.
        from securesync.domain.conflict import ConflictMetadata, ConflictType

        local_conflict = ConflictMetadata(
            conflict_id=f"sync-{relative_path}-{peer.device_id}",
            file_path=relative_path,
            conflict_type=ConflictType.CONCURRENT_MODIFICATION,
            local_version=local_version or VersionVector(),
            remote_version=peer_mv.version or VersionVector(),
            remote_device_id=peer.device_id,
        )
        remote_conflict = ConflictMetadata(
            conflict_id=f"sync-{relative_path}-local",
            file_path=relative_path,
            conflict_type=ConflictType.CONCURRENT_MODIFICATION,
            local_version=peer_mv.version or VersionVector(),
            remote_version=local_version or VersionVector(),
            remote_device_id=self._own_device_id(peer),
        )
        remote_wins = merge_strategy.merge(local_conflict, remote_conflict)
        if remote_wins:
            return await self.pull(peer, sync_root, relative_path, strategy, chunk_size=chunk_size)
        return SyncFileResult(transferred_count=0, direction=SyncDirection.NOOP.value)

    @staticmethod
    def _own_device_id(peer: Peer) -> str:
        """Best-effort 'own device id' for the conflict metadata.

        Falls back to a sentinel string when not threaded through
        the use case explicitly (Phase 17 keeps the use case
        peer-agnostic; main.py will override via a richer wiring in
        Phase 18+). The conflict ID is informational only.
        """
        return peer.address.ip_address or "local"

    async def _request_peer_manifest_with_version(
        self, peer: Peer, relative_path: str
    ) -> ManifestWithVersion | None:
        """Fetch the peer's manifest + version, normalizing the source path."""
        peer_mv = await self._manifest_exchange.request_manifest(peer, relative_path)
        if peer_mv is None:
            return None
        return peer_mv

    async def _local_manifest_or_empty(
        self, source_path: Path, strategy: ChunkingStrategy, chunk_size: int
    ) -> ChunkCollection:
        """Build the local manifest, or an empty one if `source_path` doesn't exist yet."""
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
        """Request the peer's manifest, with its path normalized to this device's own."""
        peer_mv = await self._manifest_exchange.request_manifest(peer, relative_path)
        if peer_mv is None:
            return None
        return replace(peer_mv.collection, source_path=source_path)

    async def _filter_chunks_to_upload(
        self, source_path: Path, strategy: ChunkingStrategy, needed_hashes: set[str]
    ) -> AsyncIterator[Chunk]:
        """Stream the local file's chunks, yielding only the ones the peer needs."""
        async for chunk in self._chunk_file_use_case.execute(source_path, strategy):
            chunk_hash = chunk.metadata.chunk_hash
            if chunk_hash is not None and chunk_hash.digest in needed_hashes:
                yield chunk


class LocalVersionProvider(Protocol):
    """Callable returning the local VersionVector for a relative path.

    A `Protocol` (structural typing), not a concrete base class to
    subclass — this was previously a plain class, which meant mypy
    rejected any ordinary async function passed for this parameter
    (only an actual `LocalVersionProvider` instance satisfied it) even
    though the runtime behavior — "any async callable with this
    signature" — always worked correctly; `main.py`'s Phase 21 wiring
    of a plain local function is what surfaced this.
    """

    async def __call__(self, relative_path: str) -> VersionVector | None: ...
