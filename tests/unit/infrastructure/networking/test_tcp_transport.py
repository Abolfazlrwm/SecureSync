"""Unit tests for TcpTransferTransport."""

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
from securesync.infrastructure.networking.tcp_transport import TcpTransferTransport

KEY = b"k" * 32


def _peer(device_id: str, port: int) -> Peer:
    return Peer(
        identity=PeerIdentity(device_id, f"host-{device_id}", f"fp-{device_id}"),
        address=PeerAddress("127.0.0.1", port),
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


class TestSendAndRequestChunksOverRealSockets:
    """Tests exercising the transport's own real TCP send/receive path."""

    async def test_a_sends_b_receives_over_a_real_socket(self) -> None:
        cipher = AesGcmCipher()
        transport_a = TcpTransferTransport("dev-a", "127.0.0.1", 19301, cipher, KEY)
        transport_b = TcpTransferTransport("dev-b", "127.0.0.1", 19302, cipher, KEY)
        await transport_a.start()
        await transport_b.start()
        try:
            chunk = _chunk("c1", b"hello world", "a" * 64)
            await transport_a.send_chunk(_peer("dev-b", 19302), chunk)

            received = [
                c async for c in transport_b.request_chunks(_peer("dev-a", 19301), ["a" * 64])
            ]

            assert len(received) == 1
            assert received[0].data == b"hello world"
            assert received[0].metadata.chunk_id == "c1"
        finally:
            await transport_a.stop()
            await transport_b.stop()

    async def test_bidirectional_transfer(self) -> None:
        """Each side can both send and receive over its own listening socket."""
        cipher = AesGcmCipher()
        transport_a = TcpTransferTransport("dev-a", "127.0.0.1", 19303, cipher, KEY)
        transport_b = TcpTransferTransport("dev-b", "127.0.0.1", 19304, cipher, KEY)
        await transport_a.start()
        await transport_b.start()
        try:
            await transport_a.send_chunk(_peer("dev-b", 19304), _chunk("c1", b"abc", "a" * 64))
            await transport_b.send_chunk(_peer("dev-a", 19303), _chunk("c2", b"def", "b" * 64))

            b_received = [
                c async for c in transport_b.request_chunks(_peer("dev-a", 19303), ["a" * 64])
            ]
            a_received = [
                c async for c in transport_a.request_chunks(_peer("dev-b", 19304), ["b" * 64])
            ]

            assert b_received[0].data == b"abc"
            assert a_received[0].data == b"def"
        finally:
            await transport_a.stop()
            await transport_b.stop()

    async def test_wrong_key_fails_to_decrypt(self) -> None:
        cipher = AesGcmCipher()
        transport_a = TcpTransferTransport("dev-a", "127.0.0.1", 19305, cipher, KEY)
        transport_b = TcpTransferTransport("dev-b", "127.0.0.1", 19306, cipher, b"x" * 32)
        await transport_a.start()
        await transport_b.start()
        try:
            await transport_a.send_chunk(
                _peer("dev-b", 19306), _chunk("c1", b"secret", "a" * 64)
            )

            with pytest.raises(InvalidTag):
                async for _ in transport_b.request_chunks(_peer("dev-a", 19305), ["a" * 64]):
                    pass
        finally:
            await transport_a.stop()
            await transport_b.stop()


class TestAgainstRealUseCases:
    """Confirms the real, unmodified transfer use cases work over real sockets."""

    async def test_upload_then_download_round_trips_multiple_chunks(self) -> None:
        cipher = AesGcmCipher()
        transport_a = TcpTransferTransport("dev-a", "127.0.0.1", 19307, cipher, KEY)
        transport_b = TcpTransferTransport("dev-b", "127.0.0.1", 19308, cipher, KEY)
        await transport_a.start()
        await transport_b.start()
        try:
            upload = UploadChunksUseCase(transport_a)
            download = DownloadChunksUseCase(transport_b)

            async def chunks_to_send() -> object:
                yield _chunk("c1", b"abc", "a" * 64)
                yield _chunk("c2", b"def", "b" * 64)

            await upload.execute(_peer("dev-b", 19308), chunks_to_send())
            received = [
                c
                async for c in download.execute(
                    _peer("dev-a", 19307), ["a" * 64, "b" * 64]
                )
            ]

            assert [c.data for c in received] == [b"abc", b"def"]
        finally:
            await transport_a.stop()
            await transport_b.stop()
