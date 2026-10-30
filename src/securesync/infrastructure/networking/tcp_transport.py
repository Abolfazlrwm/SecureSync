"""Real TCP implementation of the TransferTransport port.

Unlike
:class:`~securesync.infrastructure.networking.in_process_transport.InProcessTransferTransport`
(same-process only), this adapter actually opens sockets: an
``asyncio`` server accepts inbound connections and a short-lived
client connection is opened per outbound chunk. Confidentiality and
integrity are provided by the same :class:`~securesync.domain.crypto.AeadCipher`
message-level encryption `InProcessTransferTransport` uses — see
``docs/adr/0017-tcp-transfer-transport.md`` for why that means no
separate TLS layer is required for this to be genuinely secure.

Step 1d moves every message onto the v2 frame
(:mod:`securesync.infrastructure.networking.secure_channel`): the frame carries
a plaintext ``session_id``, so an inbound message is matched to its session in
O(1) instead of trial-decrypting against every known key, and the per-session
anti-replay window rejects duplicates and old counters.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from collections.abc import AsyncIterator
from typing import Any

import structlog

from securesync.core.protocol import PacketType
from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.domain.conflict import VersionVector
from securesync.domain.crypto import AeadCipher
from securesync.domain.networking import Peer
from securesync.domain.transfer import IncomingPush, TransferTransport
from securesync.infrastructure.networking.message_io import (
    _LENGTH_PREFIX_FORMAT,
    INBOX_MAX_SIZE,
    MAX_CONCURRENT_CONNECTIONS,
    MAX_MESSAGE_SIZE,
    read_length_prefixed,
)
from securesync.infrastructure.networking.replay_protection import ReplayProtectionError
from securesync.infrastructure.networking.secure_channel import SecureChannel
from securesync.infrastructure.networking.session_store import NoSessionError, SessionStore

logger = structlog.get_logger(__name__)


class TcpTransferTransport(TransferTransport):
    """Moves chunks between peers over real TCP sockets, AEAD-encrypted.

    One instance represents one local device: :meth:`start` opens a
    listening server that accepts inbound connections from any peer
    and decrypts/queues whatever chunks arrive; :meth:`send_chunk`
    opens a short-lived outbound connection per call.
    """

    def __init__(
        self,
        own_device_id: str,
        listen_host: str,
        listen_port: int,
        cipher: AeadCipher,
        sessions: SessionStore,
    ) -> None:
        """Initialize the transport.

        Args:
            own_device_id: This device's ID — used as the AAD receiver at
                receive time and the AAD sender at send time.
            listen_host: Host/interface to accept inbound connections on.
            listen_port: Port to accept inbound connections on.
            cipher: The AEAD cipher used to encrypt and decrypt every message.
            sessions: The negotiated sessions, shared with whatever
                handshake machinery and manifest transport populate them.
        """
        self._own_device_id = own_device_id
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._cipher = cipher
        self._sessions = sessions
        self._channel = SecureChannel(own_device_id, cipher, sessions)
        self._inbox: asyncio.Queue[bytes] = asyncio.Queue(maxsize=INBOX_MAX_SIZE)
        self._active_connections = 0
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        """Start accepting inbound connections.

        Raises:
            OSError: If `listen_port` can't be bound (e.g. already in use).
        """
        self._server = await asyncio.start_server(
            self._handle_connection, self._listen_host, self._listen_port
        )
        logger.info("tcp_transport_started", host=self._listen_host, port=self._listen_port)

    async def stop(self) -> None:
        """Stop accepting inbound connections and close the listening socket."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info("tcp_transport_stopped")

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Read one frame from an inbound connection and queue it.

        Each connection carries exactly one frame — matching
        :meth:`send_chunk`'s one-connection-per-chunk behavior — so
        this handler reads one, queues it, and closes the connection.
        """
        if self._active_connections >= MAX_CONCURRENT_CONNECTIONS:
            logger.warning("connection_refused_too_many", active=self._active_connections)
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()
            return

        self._active_connections += 1
        try:
            frame = await self._read_frame(reader)
            self._try_enqueue(frame)
        except (
            asyncio.IncompleteReadError,
            ConnectionError,
        ) as e:
            logger.warning("tcp_transport_connection_dropped", error=str(e))
        finally:
            self._active_connections -= 1
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    def _try_enqueue(self, frame: bytes) -> None:
        """Add a frame to the inbox, dropping it when the inbox is full."""
        try:
            self._inbox.put_nowait(frame)
        except asyncio.QueueFull:
            logger.warning("inbox_full_dropping_frame", maxsize=INBOX_MAX_SIZE)

    async def send_chunk(
        self,
        peer: Peer,
        chunk: Chunk,
        *,
        relative_path: str,
        total_chunks: int,
        version_vector: VersionVector | None = None,
    ) -> None:
        """Encrypt a chunk and send it to a peer over a short-lived TCP connection.

        Args:
            peer: The peer to send the chunk to.
            chunk: The chunk to send.
            relative_path: The file this chunk belongs to, relative to
                the sync root — see `IncomingPush` for why the
                receiving side needs this alongside the chunk itself.
            total_chunks: How many chunks make up the complete file.
            version_vector: This device's version vector for the
                file, if known.

        Raises:
            NoSessionError: If the peer has no confirmed session; the caller
                must open a new handshake.
            OSError: If a connection to `peer` can't be established.
        """
        payload = {
            "chunk_id": chunk.metadata.chunk_id,
            "index": chunk.metadata.index,
            "size": chunk.metadata.size,
            "offset": chunk.metadata.offset,
            "hash_algorithm": (
                chunk.metadata.chunk_hash.algorithm.value if chunk.metadata.chunk_hash else None
            ),
            "hash_digest": (
                chunk.metadata.chunk_hash.digest if chunk.metadata.chunk_hash else None
            ),
            "data": chunk.data,
            "relative_path": relative_path,
            "total_chunks": total_chunks,
            "version_counters": version_vector.counters if version_vector is not None else None,
        }
        # The session is looked up by the *peer's* device ID, never our own:
        # the store is keyed by the other side of each conversation.
        session = self._sessions.get_send_session(peer.device_id)
        if session is None:
            raise NoSessionError(
                f"no confirmed session for {peer.device_id!r} — a handshake must complete first"
            )
        frame = self._channel.seal(session, PacketType.CHUNK_DATA, payload)

        reader, writer = await asyncio.open_connection(
            peer.address.ip_address, session.transfer_port
        )
        try:
            writer.write(struct.pack(_LENGTH_PREFIX_FORMAT, len(frame)) + frame)
            await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()
        logger.info("chunk_sent_tcp", peer=peer.device_id, chunk_id=chunk.metadata.chunk_id)

    async def request_chunks(self, peer: Peer, chunk_hashes: list[str]) -> AsyncIterator[Chunk]:
        """Yield chunks received from `peer`, matching ``chunk_hashes``.

        Args:
            peer: The peer these chunks are expected to have come from; frames
                authenticated under a different peer's session are dropped.
            chunk_hashes: The hex digests of the chunks to wait for.

        Yields:
            Each matching :class:`Chunk`, decrypted and reconstructed,
            as it arrives.
        """
        remaining = set(chunk_hashes)
        while remaining:
            frame = await self._inbox.get()
            try:
                packet, session = self._channel.open(frame)
            except ReplayProtectionError as e:
                logger.warning("inbound_frame_rejected", error=str(e))
                continue
            if session.peer_id != peer.device_id:
                logger.warning("frame_from_unexpected_peer", peer=session.peer_id)
                continue
            digest = packet.payload.get("hash_digest")
            if digest not in remaining:
                logger.warning("unrequested_chunk_dropped", digest=digest)
                continue
            remaining.discard(digest)
            yield self._chunk_from_payload(packet.payload)

    async def receive_pushes(self) -> AsyncIterator[IncomingPush]:
        """See :meth:`TransferTransport.receive_pushes`.

        Unlike `request_chunks`, this doesn't know in advance which peer a
        message came from. The frame's plaintext ``session_id`` resolves that in
        O(1), so no trial decryption over candidate sessions is needed.
        """
        while True:
            frame = await self._inbox.get()
            try:
                packet, session = self._channel.open(frame)
            except ReplayProtectionError as e:
                logger.warning("undecryptable_push_dropped", error=str(e))
                continue
            version_counters = packet.payload.get("version_counters")
            yield IncomingPush(
                relative_path=str(packet.payload["relative_path"]),
                total_chunks=int(packet.payload["total_chunks"]),
                chunk=self._chunk_from_payload(packet.payload),
                version_vector=(
                    VersionVector(dict(version_counters)) if version_counters is not None else None
                ),
            )
            logger.debug("push_received", peer=session.peer_id)

    @staticmethod
    async def _read_frame(reader: asyncio.StreamReader) -> bytes:
        """Read one length-prefixed frame from a stream."""
        return await read_length_prefixed(reader, max_size=MAX_MESSAGE_SIZE)

    @staticmethod
    def _chunk_from_payload(payload: dict[str, Any]) -> Chunk:
        """Reconstruct a `Chunk` from a decoded packet payload."""
        chunk_hash = None
        if payload.get("hash_algorithm") is not None:
            chunk_hash = ChunkHash(
                algorithm=ChunkAlgorithm(payload["hash_algorithm"]),
                digest=str(payload["hash_digest"]),
            )
        metadata = ChunkMetadata(
            chunk_id=str(payload["chunk_id"]),
            index=int(payload["index"]),
            size=int(payload["size"]),
            offset=int(payload["offset"]),
            chunk_hash=chunk_hash,
        )
        return Chunk(metadata=metadata, data=payload["data"])
