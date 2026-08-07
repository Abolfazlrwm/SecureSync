"""Unit tests for InProcessTransferTransport."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from securesync.application.use_cases.transfer_chunks import (
    DownloadChunksUseCase,
    UploadChunksUseCase,
)
from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.domain.networking import Peer, PeerAddress, PeerCapabilities, PeerIdentity
from securesync.infrastructure.crypto.pyca_crypto import AesGcmCipher
from securesync.infrastructure.networking.in_process_transport import (
    InProcessNetwork,
    InProcessTransferTransport,
)

KEY = b"k" * 32


def _peer(device_id: str) -> Peer:
    return Peer(
        identity=PeerIdentity(device_id, f"host-{device_id}", f"fp-{device_id}"),
        address=PeerAddress("127.0.0.1", 9000),
        capabilities=PeerCapabilities("1.0"),
    )


def _chunk(chunk_id: str, data: bytes, digest: str) -> Chunk:
    metadata = ChunkMetadata(
        chunk_id=chunk_id,
        index=0,
        size=len(data),
        offset=0,
        chunk_hash=ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=digest),
    )
    return Chunk(metadata=metadata, data=data)


class TestSendAndRequestChunks:
    """Tests for the transport's own send_chunk/request_chunks pair."""

    async def test_a_sends_b_receives_the_same_chunk(self) -> None:
        """A chunk sent by one peer is received intact by its addressee."""
        network = InProcessNetwork()
        cipher = AesGcmCipher()
        transport_a = InProcessTransferTransport("dev-a", network, cipher, KEY)
        transport_b = InProcessTransferTransport("dev-b", network, cipher, KEY)
        chunk = _chunk("c1", b"hello world", "a" * 64)

        await transport_a.send_chunk(_peer("dev-b"), chunk)
        received = [c async for c in transport_b.request_chunks(_peer("dev-a"), ["a" * 64])]

        assert len(received) == 1
        assert received[0].data == b"hello world"
        assert received[0].metadata.chunk_id == "c1"

    async def test_request_chunks_ignores_unrequested_digests(self) -> None:
        """Only chunks whose hash was actually requested are yielded."""
        network = InProcessNetwork()
        cipher = AesGcmCipher()
        transport_a = InProcessTransferTransport("dev-a", network, cipher, KEY)
        transport_b = InProcessTransferTransport("dev-b", network, cipher, KEY)

        await transport_a.send_chunk(_peer("dev-b"), _chunk("c1", b"one", "a" * 64))
        await transport_a.send_chunk(_peer("dev-b"), _chunk("c2", b"two", "b" * 64))

        received = [c async for c in transport_b.request_chunks(_peer("dev-a"), ["b" * 64])]

        assert len(received) == 1
        assert received[0].metadata.chunk_id == "c2"

    async def test_wrong_key_fails_to_decrypt(self) -> None:
        """A receiver with a different key can't decrypt what was sent."""
        network = InProcessNetwork()
        cipher = AesGcmCipher()
        transport_a = InProcessTransferTransport("dev-a", network, cipher, KEY)
        transport_b = InProcessTransferTransport("dev-b", network, cipher, b"x" * 32)

        await transport_a.send_chunk(_peer("dev-b"), _chunk("c1", b"secret", "a" * 64))

        with pytest.raises(InvalidTag):
            async for _ in transport_b.request_chunks(_peer("dev-a"), ["a" * 64]):
                pass


class TestAgainstRealUseCases:
    """Confirms the real, unmodified transfer use cases work against this transport."""

    async def test_upload_then_download_round_trips_multiple_chunks(self) -> None:
        network = InProcessNetwork()
        cipher = AesGcmCipher()
        transport_a = InProcessTransferTransport("dev-a", network, cipher, KEY)
        transport_b = InProcessTransferTransport("dev-b", network, cipher, KEY)
        upload = UploadChunksUseCase(transport_a)
        download = DownloadChunksUseCase(transport_b)

        async def chunks_to_send() -> object:
            yield _chunk("c1", b"abc", "a" * 64)
            yield _chunk("c2", b"def", "b" * 64)

        await upload.execute(_peer("dev-b"), chunks_to_send())
        received = [
            c
            async for c in download.execute(_peer("dev-a"), ["a" * 64, "b" * 64])
        ]

        assert [c.data for c in received] == [b"abc", b"def"]
