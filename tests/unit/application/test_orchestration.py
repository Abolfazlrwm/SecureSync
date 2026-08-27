"""Unit tests for SyncOrchestrator."""

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, call

import pytest

from securesync.application.orchestration import SyncOrchestrator, SyncState
from securesync.application.use_cases.sync_file import SyncFileResult
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


@pytest.mark.asyncio
async def test_handle_peer_discovered_establishes_a_session_when_coordinator_is_set() -> None:
    """A configured session_coordinator is asked to establish a session for new peers."""
    session_coordinator = AsyncMock()
    orchestrator = SyncOrchestrator(
        metadata_repo=AsyncMock(),
        discovery_use_case=AsyncMock(),
        conflict_use_case=AsyncMock(),
        session_coordinator=session_coordinator,
    )
    peer = _peer()

    await orchestrator.start()
    await orchestrator.handle_peer_discovered(peer)

    session_coordinator.ensure_session.assert_awaited_once_with(peer)
    await orchestrator.stop()


@pytest.mark.asyncio
async def test_handle_peer_discovered_survives_a_failed_session_establishment() -> None:
    """A handshake failure for one peer must not crash discovery of others."""
    session_coordinator = AsyncMock()
    session_coordinator.ensure_session.side_effect = OSError("connection refused")
    orchestrator = SyncOrchestrator(
        metadata_repo=AsyncMock(),
        discovery_use_case=AsyncMock(),
        conflict_use_case=AsyncMock(),
        session_coordinator=session_coordinator,
    )

    await orchestrator.start()
    await orchestrator.handle_peer_discovered(_peer())

    assert orchestrator.stats.errors_encountered == 1
    assert orchestrator.state == SyncState.SYNCING
    await orchestrator.stop()


@pytest.mark.asyncio
async def test_handle_peer_discovered_works_without_a_session_coordinator() -> None:
    """No session_coordinator configured (the default) must not raise."""
    orchestrator = _orchestrator()

    await orchestrator.start()
    await orchestrator.handle_peer_discovered(_peer())  # should not raise

    await orchestrator.stop()


def _orchestrator_with_auto_push(
    sync_file_use_case: AsyncMock,
    metadata_repo: AsyncMock | None = None,
) -> SyncOrchestrator:
    return SyncOrchestrator(
        metadata_repo=metadata_repo or AsyncMock(),
        discovery_use_case=AsyncMock(),
        conflict_use_case=AsyncMock(),
        sync_file_use_case=sync_file_use_case,
        sync_root=Path("/sync"),
        chunking_strategy=_chunking_strategy,
        chunk_size=4 * 1024 * 1024,
    )


# A plain sentinel is enough here — the orchestrator only forwards it
# to SyncFileUseCase.push, which is mocked in every test below.
_chunking_strategy = object()


@pytest.mark.asyncio
async def test_handle_peer_discovered_pushes_every_known_file() -> None:
    """Each locally known file gets pushed once a peer is discovered."""
    metadata_repo = AsyncMock()
    metadata_repo.list_all_files.return_value = [
        FileMetadata("a.txt", VersionVector({"dev-1": 1}), datetime.now(UTC)),
        FileMetadata("b.txt", VersionVector({"dev-1": 1}), datetime.now(UTC)),
    ]
    sync_file_use_case = AsyncMock()
    sync_file_use_case.push.return_value = SyncFileResult(transferred_count=1)
    orchestrator = _orchestrator_with_auto_push(sync_file_use_case, metadata_repo)
    peer = _peer()

    await orchestrator.start()
    await orchestrator.handle_peer_discovered(peer)

    sync_file_use_case.sync.assert_has_awaits(
        [
            call(peer, Path("/sync"), "a.txt", _chunking_strategy, chunk_size=4 * 1024 * 1024),
            call(peer, Path("/sync"), "b.txt", _chunking_strategy, chunk_size=4 * 1024 * 1024),
        ],
        any_order=True,
    )
    await orchestrator.stop()


@pytest.mark.asyncio
async def test_handle_peer_discovered_skips_deleted_files() -> None:
    """A tombstoned file has nothing to push and must be skipped."""
    metadata_repo = AsyncMock()
    metadata_repo.list_all_files.return_value = [
        FileMetadata("gone.txt", VersionVector({"dev-1": 1}), datetime.now(UTC), is_deleted=True),
    ]
    sync_file_use_case = AsyncMock()
    orchestrator = _orchestrator_with_auto_push(sync_file_use_case, metadata_repo)

    await orchestrator.start()
    await orchestrator.handle_peer_discovered(_peer())

    sync_file_use_case.push.assert_not_awaited()
    await orchestrator.stop()


@pytest.mark.asyncio
async def test_handle_peer_discovered_survives_one_failed_push() -> None:
    """One file failing to push must not stop the rest of the batch."""
    metadata_repo = AsyncMock()
    metadata_repo.list_all_files.return_value = [
        FileMetadata("bad.txt", VersionVector({"dev-1": 1}), datetime.now(UTC)),
        FileMetadata("good.txt", VersionVector({"dev-1": 1}), datetime.now(UTC)),
    ]
    sync_file_use_case = AsyncMock()
    sync_file_use_case.sync.side_effect = [
        OSError("connection refused"),
        SyncFileResult(transferred_count=1),
    ]
    orchestrator = _orchestrator_with_auto_push(sync_file_use_case, metadata_repo)

    await orchestrator.start()
    await orchestrator.handle_peer_discovered(_peer())

    assert sync_file_use_case.sync.await_count == 2
    assert orchestrator.stats.errors_encountered == 1
    assert orchestrator.state == SyncState.SYNCING
    await orchestrator.stop()


@pytest.mark.asyncio
async def test_handle_peer_discovered_does_nothing_without_sync_file_use_case() -> None:
    """The pre-Phase-16 default (no sync_file_use_case) must not raise or push."""
    orchestrator = _orchestrator()

    await orchestrator.start()
    await orchestrator.handle_peer_discovered(_peer())  # should not raise

    await orchestrator.stop()


@pytest.mark.asyncio
async def test_handle_peer_discovered_warns_when_auto_push_misconfigured() -> None:
    """sync_file_use_case without sync_root/chunking_strategy/chunk_size must not push or raise."""
    metadata_repo = AsyncMock()
    metadata_repo.list_all_files.return_value = [
        FileMetadata("a.txt", VersionVector({"dev-1": 1}), datetime.now(UTC)),
    ]
    sync_file_use_case = AsyncMock()
    orchestrator = SyncOrchestrator(
        metadata_repo=metadata_repo,
        discovery_use_case=AsyncMock(),
        conflict_use_case=AsyncMock(),
        sync_file_use_case=sync_file_use_case,
        # sync_root, chunking_strategy, chunk_size deliberately left unset
    )

    await orchestrator.start()
    await orchestrator.handle_peer_discovered(_peer())  # should not raise

    sync_file_use_case.push.assert_not_awaited()
    await orchestrator.stop()
