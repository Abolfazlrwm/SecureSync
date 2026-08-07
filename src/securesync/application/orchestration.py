"""Orchestration layer coordinating all synchronization components."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import StrEnum, unique

import structlog

from securesync.application.use_cases.conflict_resolution import DetectConflictUseCase
from securesync.application.use_cases.discover_peers import DiscoverPeersUseCase
from securesync.application.use_cases.transfer_chunks import (
    DownloadChunksUseCase,
    UploadChunksUseCase,
)
from securesync.domain.metadata import MetadataRepository
from securesync.domain.networking import Peer

logger = structlog.get_logger()

#: How often (seconds) the sync loop polls for newly online peers.
_POLL_INTERVAL_SECONDS = 5


@unique
class SyncState(StrEnum):
    """Possible states of the synchronization engine."""

    IDLE = "idle"
    SCANNING = "scanning"
    SYNCING = "syncing"
    PAUSED = "paused"
    ERROR = "error"


@dataclass
class SyncStats:
    """Aggregated metrics for the current synchronization session."""

    files_processed: int = 0
    bytes_transferred: int = 0
    conflicts_detected: int = 0
    errors_encountered: int = 0


class SyncOrchestrator:
    """The central coordinator for SecureSync's operations.

    This class wires together discovery, transfer, metadata, and
    conflict resolution into a cohesive synchronization service.
    ``download_use_case``/``upload_use_case`` are optional: a real
    peer-to-peer chunk transport
    (:class:`~securesync.infrastructure.networking.in_process_transport.InProcessTransferTransport`
    for same-process peer pairs today; a socket-based adapter is
    future work — see ``docs/adr/0016-in-process-encrypted-transport.md``)
    can be supplied once available; without one, the orchestrator still
    discovers peers and tracks local file metadata, it just can't move
    chunk bytes yet.
    """

    def __init__(
        self,
        metadata_repo: MetadataRepository,
        discovery_use_case: DiscoverPeersUseCase,
        conflict_use_case: DetectConflictUseCase,
        download_use_case: DownloadChunksUseCase | None = None,
        upload_use_case: UploadChunksUseCase | None = None,
    ) -> None:
        """Initialize the orchestrator.

        Args:
            metadata_repo: Store for locally known file metadata.
            discovery_use_case: Discovers and tracks peers on the network.
            conflict_use_case: Detects version conflicts between local
                and remote file metadata.
            download_use_case: Downloads chunks from a peer, if a real
                transport is available.
            upload_use_case: Uploads chunks to a peer, if a real
                transport is available.
        """
        self._metadata_repo = metadata_repo
        self._discovery_use_case = discovery_use_case
        self._download_use_case = download_use_case
        self._upload_use_case = upload_use_case
        self._conflict_use_case = conflict_use_case

        self._state = SyncState.IDLE
        self._stats = SyncStats()
        self._active_peers: set[str] = set()
        self._sync_task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()

    @property
    def state(self) -> SyncState:
        """The orchestrator's current lifecycle state."""
        return self._state

    @property
    def stats(self) -> SyncStats:
        """A snapshot of the current session's aggregated metrics."""
        return self._stats

    async def start(self) -> None:
        """Start the synchronization engine, including real peer discovery."""
        if self._state != SyncState.IDLE:
            return

        self._state = SyncState.SCANNING
        self._stop_event.clear()
        await self._discovery_use_case.start()
        self._sync_task = asyncio.create_task(self._run_sync_loop())
        logger.info("orchestrator_started")

    async def stop(self) -> None:
        """Stop the synchronization engine gracefully, including peer discovery."""
        self._stop_event.set()
        if self._sync_task:
            await self._sync_task
        await self._discovery_use_case.stop()
        self._state = SyncState.IDLE
        logger.info("orchestrator_stopped")

    async def wait_until_stopped(self) -> None:
        """Block until :meth:`stop` has been called and processed.

        Intended for a composition root's main loop — e.g.
        ``await orchestrator.wait_until_stopped()`` after
        :meth:`start` — so callers never need to reach into this
        class's internals to wait on its lifecycle.
        """
        await self._stop_event.wait()

    async def pause(self) -> None:
        """Temporarily pause synchronization."""
        self._state = SyncState.PAUSED
        logger.info("orchestrator_paused")

    async def resume(self) -> None:
        """Resume a paused synchronization engine."""
        if self._state == SyncState.PAUSED:
            self._state = SyncState.SYNCING
            logger.info("orchestrator_resumed")

    async def _run_sync_loop(self) -> None:
        """Background loop that reacts to newly discovered peers.

        Polls :meth:`DiscoverPeersUseCase.list_online_peers` every
        :data:`_POLL_INTERVAL_SECONDS` seconds — peer discovery itself
        is push-based (:class:`~securesync.domain.networking.DiscoveryService`
        notifies :attr:`_discovery_use_case` the moment a peer appears),
        but bridging that into this loop's reaction is deliberately
        poll-based for simplicity, since a 5-second detection latency is
        immaterial for local-network peer sync.
        """
        try:
            while not self._stop_event.is_set():
                if self._state == SyncState.PAUSED:
                    await self._wait_or_timeout(1)
                    continue

                online_peers = await self._discovery_use_case.list_online_peers()
                new_peers = [
                    peer for peer in online_peers if peer.device_id not in self._active_peers
                ]
                for peer in new_peers:
                    await self.handle_peer_discovered(peer)

                await self._wait_or_timeout(_POLL_INTERVAL_SECONDS)

        except Exception as e:
            self._state = SyncState.ERROR
            self._stats.errors_encountered += 1
            logger.error("orchestrator_loop_failed", error=str(e))
        finally:
            self._state = SyncState.IDLE

    async def _wait_or_timeout(self, seconds: float) -> None:
        """Sleep for ``seconds``, returning immediately if stopped first.

        Using ``asyncio.wait_for`` on :attr:`_stop_event` instead of a
        plain ``asyncio.sleep`` means :meth:`stop` doesn't have to wait
        out an in-progress poll interval before the loop notices it
        should exit.
        """
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
        except TimeoutError:
            pass

    async def handle_peer_discovered(self, peer: Peer) -> None:
        """React to a new peer being discovered.

        Marks the peer active and refreshes the count of locally known
        files against :attr:`_metadata_repo`. Actually exchanging
        manifests and chunks with ``peer`` requires a remote-manifest
        RPC this codebase doesn't implement yet (see
        ``docs/adr/0016-in-process-encrypted-transport.md``); when
        that lands, this is the method that will call
        :attr:`_conflict_use_case` per file and then
        :attr:`_download_use_case`/:attr:`_upload_use_case` for
        whatever :class:`~securesync.domain.delta.DeltaPlan` results.

        Args:
            peer: The newly discovered, online peer.
        """
        self._active_peers.add(peer.device_id)
        logger.info("peer_added_to_sync", device_id=peer.device_id)

        local_files = await self._metadata_repo.list_all_files()
        self._stats.files_processed = len(local_files)

        if self._download_use_case is None or self._upload_use_case is None:
            logger.info(
                "chunk_transfer_not_available",
                device_id=peer.device_id,
                reason="no TransferTransport configured",
            )

        if self._state == SyncState.SCANNING:
            self._state = SyncState.SYNCING
