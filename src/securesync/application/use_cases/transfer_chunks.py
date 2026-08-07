"""Use cases for transferring chunks between peers."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence

import structlog

from securesync.domain.chunk import Chunk
from securesync.domain.networking import Peer
from securesync.domain.transfer import TransferTransport

logger = structlog.get_logger()


class DownloadChunksUseCase:
    """Orchestrates downloading chunks from a peer."""

    def __init__(self, transport: TransferTransport) -> None:
        self._transport = transport

    async def execute(self, peer: Peer, chunk_hashes: Sequence[str]) -> AsyncIterator[Chunk]:
        """Download multiple chunks from a peer.

        Args:
            peer: The peer to download from.
            chunk_hashes: Hashes of the chunks to request.

        Yields:
            The downloaded chunks.
        """
        logger.info("download_started", peer_id=peer.device_id, chunk_count=len(chunk_hashes))

        async for chunk in self._transport.request_chunks(peer, list(chunk_hashes)):
            yield chunk

        logger.info("download_finished", peer_id=peer.device_id)


class UploadChunksUseCase:
    """Orchestrates uploading chunks to a peer."""

    def __init__(self, transport: TransferTransport) -> None:
        self._transport = transport

    async def execute(self, peer: Peer, chunks: AsyncIterator[Chunk]) -> None:
        """Upload chunks to a peer.

        Args:
            peer: The peer to upload to.
            chunks: An iterator of chunks to send.
        """
        logger.info("upload_started", peer_id=peer.device_id)

        count = 0
        async for chunk in chunks:
            await self._transport.send_chunk(peer, chunk)
            count += 1

        logger.info("upload_finished", peer_id=peer.device_id, chunks_sent=count)
