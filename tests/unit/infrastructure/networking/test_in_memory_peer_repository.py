"""Unit tests for InMemoryPeerRepository."""

import pytest

from securesync.domain.networking import (
    Peer,
    PeerAddress,
    PeerCapabilities,
    PeerIdentity,
)
from securesync.infrastructure.networking.in_memory_peer_repository import InMemoryPeerRepository


@pytest.mark.asyncio
async def test_in_memory_repo_save_and_get() -> None:
    repo = InMemoryPeerRepository()
    peer = Peer(
        PeerIdentity("d1", "h1", "f1"), PeerAddress("1.1.1.1", 1111), PeerCapabilities("1.0")
    )

    await repo.save(peer)
    retrieved = await repo.get_by_id("d1")

    assert retrieved == peer


@pytest.mark.asyncio
async def test_in_memory_repo_list_all() -> None:
    repo = InMemoryPeerRepository()
    peer1 = Peer(PeerIdentity("d1", "h1", "f1"), PeerAddress("1", 1), PeerCapabilities("1"))
    peer2 = Peer(PeerIdentity("d2", "h2", "f2"), PeerAddress("2", 2), PeerCapabilities("2"))

    await repo.save(peer1)
    await repo.save(peer2)

    all_peers = await repo.list_all()
    assert len(all_peers) == 2
    assert peer1 in all_peers
    assert peer2 in all_peers


@pytest.mark.asyncio
async def test_in_memory_repo_remove() -> None:
    repo = InMemoryPeerRepository()
    peer = Peer(PeerIdentity("d1", "h1", "f1"), PeerAddress("1", 1), PeerCapabilities("1"))

    await repo.save(peer)
    await repo.remove("d1")

    assert await repo.get_by_id("d1") is None
