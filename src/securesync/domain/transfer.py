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
from securesync.domain.conflict import VersionVector
from securesync.domain.networking import Peer


@dataclass(frozen=True, slots=True)
class TransferProgress:
    """Progress report for an ongoing transfer."""

    device_id: str
    file_path: str
    bytes_transferred: int
    total_bytes: int
    is_complete: bool = False


@dataclass(frozen=True, slots=True)
class IncomingPush:
    """One chunk of an unsolicited push, with enough context to reconstruct it.

    Phase 20's end-to-end test (ADR-0025) found that a pushed chunk's
    wire payload carried no file identity at all — a receiver had no
    way to know which file an arriving chunk belonged to, or when a
    file's chunks were all in. `relative_path` and `total_chunks` (added
    in Phase 21, see ADR-0026) close that gap; `chunk` already knows
    its own offset within the file via `chunk.metadata.offset`.

    Attributes:
        relative_path: The file this chunk belongs to, relative to
            both peers' sync roots (never an absolute path — the two
            peers' filesystem layouts can differ; see ADR-0022).
        total_chunks: How many chunks make up the complete file, so a
            receiver knows when it's seen all of them.
        chunk: The chunk itself.
        version_vector: The sender's version vector for the file, if
            it provided one (`None` for legacy/no-version senders).
    """

    relative_path: str
    total_chunks: int
    chunk: Chunk
    version_vector: VersionVector | None = None


class TransferTransport(ABC):
    """Port for the underlying network transport."""

    @abstractmethod
    async def send_chunk(
        self,
        peer: Peer,
        chunk: Chunk,
        *,
        relative_path: str,
        total_chunks: int,
        version_vector: VersionVector | None = None,
    ) -> None:
        """Send a single chunk to a peer.

        Args:
            peer: The peer to send the chunk to.
            chunk: The chunk to send.
            relative_path: The file this chunk belongs to, relative to
                the sync root (see `IncomingPush` for why this needs
                to travel with the chunk).
            total_chunks: How many chunks make up the complete file.
            version_vector: This device's version vector for the
                file, if known — see `IncomingPush.version_vector`.
        """
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

    @abstractmethod
    async def receive_pushes(self) -> AsyncIterator[IncomingPush]:
        """Yield every unsolicited pushed chunk as it arrives, from any peer.

        Unlike `request_chunks` (which waits for specific hashes a
        caller already knows to expect — used by `pull`, per
        ADR-0022), this drains whatever arrives unconditionally, with
        no prior knowledge of what's coming. It's how a `push`
        (ADR-0023/0024) is received on the other end: see
        `ReceivePushedFilesUseCase` and ADR-0026.

        Implementations must be real async generators, for the same
        reason as `request_chunks` above.
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
