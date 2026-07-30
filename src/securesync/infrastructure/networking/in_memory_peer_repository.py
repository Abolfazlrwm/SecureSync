"""In-memory implementation of the PeerRepository port."""

from __future__ import annotations

import asyncio

from securesync.domain.networking import Peer, PeerRepository


class InMemoryPeerRepository(PeerRepository):
    """A thread-safe in-memory store for peers.

    Useful for testing and as a temporary store before the SQLite
    adapter is implemented in Phase 8.
    """

    def __init__(self) -> None:
        self._peers: dict[str, Peer] = {}
        self._lock = asyncio.Lock()

    async def save(self, peer: Peer) -> None:
        """See :meth:`PeerRepository.save`."""
        async with self._lock:
            self._peers[peer.device_id] = peer

    async def get_by_id(self, device_id: str) -> Peer | None:
        """See :meth:`PeerRepository.get_by_id`."""
        async with self._lock:
            return self._peers.get(device_id)

    async def list_all(self) -> list[Peer]:
        """See :meth:`PeerRepository.list_all`."""
        async with self._lock:
            return list(self._peers.values())

    async def remove(self, device_id: str) -> None:
        """See :meth:`PeerRepository.remove`."""
        async with self._lock:
            if device_id in self._peers:
                del self._peers[device_id]
