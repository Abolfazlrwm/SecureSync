"""Unit tests for DiscoverPeersUseCase."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from securesync.application.use_cases.discover_peers import DiscoverPeersUseCase
from securesync.domain.networking import (
    Peer,
    PeerAddress,
    PeerCapabilities,
    PeerIdentity,
    PeerStatus,
)


@pytest.mark.asyncio
async def test_discover_peers_start_stop() -> None:
    discovery_service = MagicMock()
    discovery_service.start = AsyncMock()
    discovery_service.stop = AsyncMock()
    peer_repo = MagicMock()

    use_case = DiscoverPeersUseCase(discovery_service, peer_repo)

    await use_case.start()
    discovery_service.subscribe.assert_called_once_with(use_case)
    discovery_service.start.assert_called_once()

    await use_case.stop()
    discovery_service.stop.assert_called_once()
    discovery_service.unsubscribe.assert_called_once_with(use_case)


@pytest.mark.asyncio
async def test_on_peer_discovered_saves_to_repo() -> None:
    discovery_service = MagicMock()
    peer_repo = MagicMock()
    peer_repo.save = AsyncMock()

    use_case = DiscoverPeersUseCase(discovery_service, peer_repo)

    peer = Peer(
        PeerIdentity("d1", "h1", "f1"),
        PeerAddress("1.2.3.4", 5678),
        PeerCapabilities("0.1"),
        status=PeerStatus.UNKNOWN,
    )

    await use_case.on_peer_discovered(peer)

    # Verify it was saved with ONLINE status
    saved_peer = peer_repo.save.call_args[0][0]
    assert saved_peer.device_id == "d1"
    assert saved_peer.status == PeerStatus.ONLINE


@pytest.mark.asyncio
async def test_on_peer_lost_updates_status() -> None:
    discovery_service = MagicMock()
    peer_repo = MagicMock()

    peer = Peer(
        PeerIdentity("d1", "h1", "f1"),
        PeerAddress("1.2.3.4", 5678),
        PeerCapabilities("0.1"),
        status=PeerStatus.ONLINE,
    )
    peer_repo.get_by_id = AsyncMock(return_value=peer)
    peer_repo.save = AsyncMock()

    use_case = DiscoverPeersUseCase(discovery_service, peer_repo)

    await use_case.on_peer_lost("d1")

    # Verify it was updated to OFFLINE
    saved_peer = peer_repo.save.call_args[0][0]
    assert saved_peer.device_id == "d1"
    assert saved_peer.status == PeerStatus.OFFLINE
