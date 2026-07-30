"""Unit tests for transfer use cases."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from securesync.application.use_cases.transfer_chunks import (
    DownloadChunksUseCase,
    UploadChunksUseCase,
)
from securesync.domain.chunk import Chunk, ChunkHash, ChunkMetadata
from securesync.domain.networking import Peer, PeerAddress, PeerCapabilities, PeerIdentity


@pytest.fixture
def mock_peer() -> Peer:
    return Peer(
        PeerIdentity("d1", "h1", "f1"), PeerAddress("1.1.1.1", 1111), PeerCapabilities("1.0")
    )


@pytest.mark.asyncio
async def test_download_chunks_use_case(mock_peer) -> None:
    transport = MagicMock()
    chunk = Chunk(
        metadata=ChunkMetadata("c1", 0, 10, 0, ChunkHash("sha256", "a" * 64)), data=b"0" * 10
    )

    def mock_request(*args, **kwargs):
        async def gen():
            yield chunk

        return gen()

    transport.request_chunks = mock_request

    use_case = DownloadChunksUseCase(transport)
    result = []
    async for c in use_case.execute(mock_peer, ["a" * 64]):
        result.append(c)

    assert result == [chunk]


@pytest.mark.asyncio
async def test_upload_chunks_use_case(mock_peer) -> None:
    transport = MagicMock()
    transport.send_chunk = AsyncMock()

    chunk = Chunk(
        metadata=ChunkMetadata("c1", 0, 10, 0, ChunkHash("sha256", "a" * 64)), data=b"0" * 10
    )

    async def chunk_gen():
        yield chunk

    use_case = UploadChunksUseCase(transport)
    await use_case.execute(mock_peer, chunk_gen())

    transport.send_chunk.assert_called_once_with(mock_peer, chunk)
