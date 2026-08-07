"""Domain ports and entities for the Transfer Engine.

Defines how chunks are transferred between peers, isolating the
transport (TCP/TLS) from the sync logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Protocol

from securesync.domain.chunk import Chunk
from securesync.domain.networking import Peer


@dataclass(frozen=True, slots=True)
class TransferProgress:
    """Progress report for an ongoing transfer."""

    device_id: str
    file_path: str
    bytes_transferred: int
    total_bytes: int
    is_complete: bool = False


class TransferTransport(ABC):
    """Port for the underlying network transport."""

    @abstractmethod
    async def send_chunk(self, peer: Peer, chunk: Chunk) -> None:
        """Send a single chunk to a peer."""
        raise NotImplementedError

    @abstractmethod
    async def request_chunks(self, peer: Peer, chunk_hashes: list[str]) -> AsyncIterator[Chunk]:
        """Request multiple chunks from a peer.

        Implementations must be real async generators (using ``yield``)
        so that callers can iterate the result directly with
        ``async for chunk in transport.request_chunks(...)`` — never a
        coroutine that itself returns an iterator, which would need an
        extra ``await`` before iteration.
        """
        raise NotImplementedError
        yield  # pragma: no cover — unreachable; makes this an async generator function


class TransferSession(ABC):
    """Port representing an active communication session with a peer."""

    @property
    @abstractmethod
    def peer(self) -> Peer:
        """The peer this session is with."""
        raise NotImplementedError

    @abstractmethod
    async def close(self) -> None:
        """Close the session."""
        raise NotImplementedError


class ChunkSender(Protocol):
    """Abstraction for sending chunks."""

    async def send(self, chunk: Chunk) -> None:
        """Send a chunk."""
        ...


class ChunkReceiver(Protocol):
    """Abstraction for receiving chunks."""

    async def receive(self) -> AsyncIterator[Chunk]:
        """Receive chunks."""
        ...
