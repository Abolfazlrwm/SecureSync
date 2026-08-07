"""Unit tests for SyncOrchestrator."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from securesync.application.orchestration import SyncOrchestrator, SyncState
from securesync.domain.conflict import VersionVector
from securesync.domain.metadata import FileMetadata
from securesync.domain.networking import (
    Peer,
    PeerAddress,
    PeerCapabilities,
    PeerIdentity,
    PeerStatus,
)


def _peer(device_id: str = "dev-1") -> Peer:
    return Peer(
        identity=PeerIdentity(device_id, f"host-{device_id}", f"fingerprint-{device_id}"),
        address=PeerAddress("127.0.0.1", 8080),
        capabilities=PeerCapabilities("1.0"),
        status=PeerStatus.ONLINE,
    )


def _orchestrator(
    metadata_repo: AsyncMock | None = None,
    discovery_use_case: AsyncMock | None = None,
) -> SyncOrchestrator:
    return SyncOrchestrator(
        metadata_repo=metadata_repo or AsyncMock(),
        discovery_use_case=discovery_use_case or AsyncMock(),
        conflict_use_case=AsyncMock(),
    )


@pytest.mark.asyncio
async def test_orchestrator_lifecycle() -> None:
    orchestrator = _orchestrator()

    assert orchestrator.state == SyncState.IDLE

    await orchestrator.start()
    assert orchestrator.state == SyncState.SCANNING

    await orchestrator.pause()
    assert orchestrator.state == SyncState.PAUSED

    await orchestrator.resume()
    assert orchestrator.state == SyncState.SYNCING

    await orchestrator.stop()
    assert orchestrator.state == SyncState.IDLE


@pytest.mark.asyncio
async def test_start_actually_starts_discovery() -> None:
    """`start()` calls through to the real discovery use case, not just a state flag."""
    discovery_use_case = AsyncMock()
    orchestrator = _orchestrator(discovery_use_case=discovery_use_case)

    await orchestrator.start()

    discovery_use_case.start.assert_awaited_once()
    await orchestrator.stop()


@pytest.mark.asyncio
async def test_stop_actually_stops_discovery() -> None:
    """`stop()` calls through to the real discovery use case, not just a state flag."""
    discovery_use_case = AsyncMock()
    orchestrator = _orchestrator(discovery_use_case=discovery_use_case)

    await orchestrator.start()
    await orchestrator.stop()

    discovery_use_case.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_handle_peer_discovered_refreshes_file_count_from_metadata_repo() -> None:
    """Discovering a peer reads real file counts from the metadata repository."""
    metadata_repo = AsyncMock()
    metadata_repo.list_all_files.return_value = [
        FileMetadata("a.txt", VersionVector({"dev-1": 1}), datetime.now(UTC)),
        FileMetadata("b.txt", VersionVector({"dev-1": 1}), datetime.now(UTC)),
    ]
    orchestrator = _orchestrator(metadata_repo=metadata_repo)

    await orchestrator.start()
    await orchestrator.handle_peer_discovered(_peer())

    assert orchestrator.stats.files_processed == 2
    metadata_repo.list_all_files.assert_awaited()
    await orchestrator.stop()


@pytest.mark.asyncio
async def test_handle_peer_discovered_transitions_scanning_to_syncing() -> None:
    orchestrator = _orchestrator()

    await orchestrator.start()
    assert orchestrator.state == SyncState.SCANNING

    await orchestrator.handle_peer_discovered(_peer())
    assert orchestrator.state == SyncState.SYNCING

    await orchestrator.stop()


@pytest.mark.asyncio
async def test_sync_loop_reacts_to_peers_returned_by_discovery() -> None:
    """The background loop itself discovers and reacts to online peers, not just direct calls."""
    import asyncio

    discovery_use_case = AsyncMock()
    discovery_use_case.list_online_peers.return_value = [_peer("dev-2")]
    orchestrator = _orchestrator(discovery_use_case=discovery_use_case)

    await orchestrator.start()
    for _ in range(50):
        if orchestrator.state == SyncState.SYNCING:
            break
        await asyncio.sleep(0.01)

    assert orchestrator.state == SyncState.SYNCING
    await orchestrator.stop()


@pytest.mark.asyncio
async def test_stop_returns_promptly_without_waiting_out_the_poll_interval() -> None:
    """stop() must not block for the full poll interval once the loop is mid-sleep."""
    import asyncio
    import time

    orchestrator = _orchestrator()
    await orchestrator.start()
    await asyncio.sleep(0.01)  # let the loop enter its poll wait

    start_time = time.monotonic()
    await orchestrator.stop()
    elapsed = time.monotonic() - start_time

    assert elapsed < 1.0
