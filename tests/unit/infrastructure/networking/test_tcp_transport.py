"""Unit tests for TcpTransferTransport over real sockets (v2 frames)."""

from __future__ import annotations

import asyncio

import pytest

from securesync.application.use_cases.transfer_chunks import (
    DownloadChunksUseCase,
    UploadChunksUseCase,
)
from securesync.core.protocol import PacketType
from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.domain.conflict import VersionVector
from securesync.domain.networking import Peer, PeerAddress, PeerCapabilities, PeerIdentity
from securesync.infrastructure.crypto.pyca_crypto import AesGcmCipher
from securesync.infrastructure.networking.replay_protection import AuthenticationError
from securesync.infrastructure.networking.secure_channel import SecureChannel
from securesync.infrastructure.networking.session_store import PeerSession, SessionStore
from securesync.infrastructure.networking.tcp_transport import TcpTransferTransport
from tests.support.sessions import paired_sessions, stores_with_pair


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
        stores = stores_with_pair(responder_transfer_port=19302)
        transport_a = TcpTransferTransport("dev-a", "127.0.0.1", 19301, cipher, stores[0])
        transport_b = TcpTransferTransport("dev-b", "127.0.0.1", 19302, cipher, stores[1])
        await transport_a.start()
        await transport_b.start()
        try:
            chunk = _chunk("c1", b"hello world", "a" * 64)
            await transport_a.send_chunk(
                _peer("dev-b", 19302), chunk, relative_path="f.txt", total_chunks=1
            )

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
        stores = stores_with_pair(initiator_transfer_port=19303, responder_transfer_port=19304)
        transport_a = TcpTransferTransport("dev-a", "127.0.0.1", 19303, cipher, stores[0])
        transport_b = TcpTransferTransport("dev-b", "127.0.0.1", 19304, cipher, stores[1])
        await transport_a.start()
        await transport_b.start()
        try:
            await transport_a.send_chunk(
                _peer("dev-b", 19304),
                _chunk("c1", b"abc", "a" * 64),
                relative_path="f.txt",
                total_chunks=1,
            )
            await transport_b.send_chunk(
                _peer("dev-a", 19303),
                _chunk("c2", b"def", "b" * 64),
                relative_path="g.txt",
                total_chunks=1,
            )

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

    async def test_wrong_receive_key_cannot_open_the_frame(self) -> None:
        """A responder whose session holds the wrong key cannot authenticate."""
        cipher = AesGcmCipher()
        session_a, session_b = paired_sessions()
        tampered_b = PeerSession(
            peer_id=session_b.peer_id,
            session_id=session_b.session_id,
            role=session_b.role,
            send_key=session_b.send_key,
            receive_key=b"\x00" * 32,  # wrong key
            transfer_port=session_b.transfer_port,
            manifest_port=session_b.manifest_port,
            confirmed=True,
        )
        channel_a = SecureChannel("dev-a", cipher, _store_with(session_a))
        channel_b = SecureChannel("dev-b", cipher, _store_with(tampered_b))

        frame = channel_a.seal(session_a, PacketType.HEARTBEAT, {"x": 1})

        with pytest.raises(AuthenticationError):
            channel_b.open(frame)


def _store_with(session: PeerSession) -> SessionStore:
    store = SessionStore()
    store.put(session)
    return store


class TestAgainstRealUseCases:
    """Confirms the real, unmodified transfer use cases work over real sockets."""

    async def test_upload_then_download_round_trips_multiple_chunks(self) -> None:
        cipher = AesGcmCipher()
        stores = stores_with_pair(responder_transfer_port=19308)
        transport_a = TcpTransferTransport("dev-a", "127.0.0.1", 19307, cipher, stores[0])
        transport_b = TcpTransferTransport("dev-b", "127.0.0.1", 19308, cipher, stores[1])
        await transport_a.start()
        await transport_b.start()
        try:
            upload = UploadChunksUseCase(transport_a)
            download = DownloadChunksUseCase(transport_b)

            async def chunks_to_send() -> object:
                yield _chunk("c1", b"abc", "a" * 64)
                yield _chunk("c2", b"def", "b" * 64)

            await upload.execute(
                _peer("dev-b", 19308), chunks_to_send(), relative_path="f.txt", total_chunks=2
            )
            received = [
                c async for c in download.execute(_peer("dev-a", 19307), ["a" * 64, "b" * 64])
            ]

            assert [c.data for c in received] == [b"abc", b"def"]
        finally:
            await transport_a.stop()
            await transport_b.stop()


class TestReceivePushesOverRealSockets:
    """Tests for the autonomous-push-reception side (ADR-0026)."""

    async def test_receive_pushes_yields_relative_path_and_version(self) -> None:
        cipher = AesGcmCipher()
        stores = stores_with_pair(responder_transfer_port=19310)
        transport_a = TcpTransferTransport("dev-a", "127.0.0.1", 19309, cipher, stores[0])
        transport_b = TcpTransferTransport("dev-b", "127.0.0.1", 19310, cipher, stores[1])
        await transport_a.start()
        await transport_b.start()
        try:
            await transport_a.send_chunk(
                _peer("dev-b", 19310),
                _chunk("c1", b"hello", "a" * 64),
                relative_path="f.txt",
                total_chunks=1,
                version_vector=VersionVector({"dev-a": 2}),
            )

            received = []
            async for push in transport_b.receive_pushes():
                received.append(push)
                break

            assert received[0].relative_path == "f.txt"
            assert received[0].total_chunks == 1
            assert received[0].chunk.data == b"hello"
            assert received[0].version_vector == VersionVector({"dev-a": 2})
        finally:
            await transport_a.stop()
            await transport_b.stop()

    async def test_receive_pushes_resolves_the_sender_from_the_session_id(self) -> None:
        """With sessions for two peers, a push still resolves in O(1)."""
        cipher = AesGcmCipher()
        store_a, store_b = stores_with_pair(responder_transfer_port=19312)
        # A third peer's session lives in B's store but is unrelated to the push.
        _, unrelated = paired_sessions(
            initiator_id="dev-c",
            responder_id="dev-b",
            salt=b"\x09" * 16,
        )
        store_b.put(unrelated)

        transport_a = TcpTransferTransport("dev-a", "127.0.0.1", 19311, cipher, store_a)
        transport_b = TcpTransferTransport("dev-b", "127.0.0.1", 19312, cipher, store_b)
        await transport_a.start()
        await transport_b.start()
        try:
            await transport_a.send_chunk(
                _peer("dev-b", 19312),
                _chunk("c1", b"hello", "a" * 64),
                relative_path="f.txt",
                total_chunks=1,
            )

            received = []
            async for push in transport_b.receive_pushes():
                received.append(push)
                break

            assert received[0].chunk.data == b"hello"
        finally:
            await transport_a.stop()
            await transport_b.stop()


class TestOwnSessionPortRegression:
    """Regression test for the own-session/own-port bug carried over from 1c.

    The original transport looked its keys up by ``own_device_id`` and dialled
    its *own* transfer port, so every real multi-peer send silently failed (or
    looped the chunk back to itself). These tests are behavioural: they only
    pass if the lookup uses the peer's session and the connection goes to the
    peer's port.
    """

    async def test_session_lookup_uses_the_peer_id_not_own_id(self) -> None:
        stores = stores_with_pair(initiator_transfer_port=19321, responder_transfer_port=19322)
        store_a = stores[0]
        # A's store holds exactly one session, and it is B's — keyed by B's id.
        assert store_a.get_send_session("dev-a") is None
        assert store_a.get_send_session("dev-b") is not None

    async def test_chunk_goes_to_the_peers_port_not_our_own(self) -> None:
        cipher = AesGcmCipher()
        store_a, store_b = stores_with_pair(
            initiator_transfer_port=19321, responder_transfer_port=19322
        )
        transport_a = TcpTransferTransport("dev-a", "127.0.0.1", 19321, cipher, store_a)
        transport_b = TcpTransferTransport("dev-b", "127.0.0.1", 19322, cipher, store_b)
        await transport_a.start()
        await transport_b.start()
        try:
            await transport_a.send_chunk(
                _peer("dev-b", 19322),
                _chunk("c1", b"to-b", "a" * 64),
                relative_path="f.txt",
                total_chunks=1,
            )

            received = await asyncio.wait_for(
                _collect(transport_b.request_chunks(_peer("dev-a", 19321), ["a" * 64])),
                timeout=2,
            )

            assert [c.data for c in received] == [b"to-b"]
            # The frame must not have looped back into A's own inbox.
            assert transport_a._inbox.empty()
        finally:
            await transport_a.stop()
            await transport_b.stop()

    async def test_messages_authenticate_in_both_directions(self) -> None:
        cipher = AesGcmCipher()
        store_a, store_b = stores_with_pair(
            initiator_transfer_port=19323, responder_transfer_port=19324
        )
        transport_a = TcpTransferTransport("dev-a", "127.0.0.1", 19323, cipher, store_a)
        transport_b = TcpTransferTransport("dev-b", "127.0.0.1", 19324, cipher, store_b)
        await transport_a.start()
        await transport_b.start()
        try:
            await transport_a.send_chunk(
                _peer("dev-b", 19324),
                _chunk("c1", b"a-to-b", "a" * 64),
                relative_path="f.txt",
                total_chunks=1,
            )
            await transport_b.send_chunk(
                _peer("dev-a", 19323),
                _chunk("c2", b"b-to-a", "b" * 64),
                relative_path="g.txt",
                total_chunks=1,
            )

            at_b = [c async for c in transport_b.request_chunks(_peer("dev-a", 19323), ["a" * 64])]
            at_a = [c async for c in transport_a.request_chunks(_peer("dev-b", 19324), ["b" * 64])]

            assert [c.data for c in at_b] == [b"a-to-b"]
            assert [c.data for c in at_a] == [b"b-to-a"]
        finally:
            await transport_a.stop()
            await transport_b.stop()


async def _collect(source: object) -> list[Chunk]:
    """Materialise an async iterator into a list (so it can be timed out)."""
    return [chunk async for chunk in source]  # type: ignore[attr-defined]


class TestConnectionLimits:
    """Tests for the DoS defenses added in Step 1c."""

    async def test_refuses_connection_when_at_capacity(self) -> None:
        """A peer cannot open an unbounded number of inbound sockets."""
        from securesync.infrastructure.networking.message_io import MAX_CONCURRENT_CONNECTIONS

        transport = TcpTransferTransport("dev-a", "127.0.0.1", 0, AesGcmCipher(), SessionStore())
        transport._active_connections = MAX_CONCURRENT_CONNECTIONS

        class _FakeReader:
            async def readexactly(self, n: int) -> bytes:  # pragma: no cover
                raise AssertionError("should not read when at connection cap")

        class _FakeWriter:
            def __init__(self) -> None:
                self.closed = False
                self._wait_closed_called = False

            def close(self) -> None:
                self.closed = True

            async def wait_closed(self) -> None:
                self._wait_closed_called = True

        fake_reader = _FakeReader()
        fake_writer = _FakeWriter()

        await transport._handle_connection(fake_reader, fake_writer)  # type: ignore[arg-type]

        assert fake_writer.closed
        assert fake_writer._wait_closed_called
        assert transport._active_connections == MAX_CONCURRENT_CONNECTIONS

    async def test_inbox_full_drops_frame(self) -> None:
        """A flooding peer cannot grow the unbounded inbound queue."""

        transport = TcpTransferTransport("dev-a", "127.0.0.1", 0, AesGcmCipher(), SessionStore())
        transport._inbox = asyncio.Queue(maxsize=1)
        transport._inbox.put_nowait(b"existing")

        transport._try_enqueue(b"overflow")

        assert transport._inbox.qsize() == 1
        assert transport._inbox.get_nowait() == b"existing"
