"""Real TCP implementation of the TransferTransport port.

Unlike
:class:`~securesync.infrastructure.networking.in_process_transport.InProcessTransferTransport`
(same-process only), this adapter actually opens sockets: an
``asyncio`` server accepts inbound connections and a short-lived
client connection is opened per outbound chunk. Confidentiality and
integrity are provided by the same :class:`~securesync.domain.crypto.AeadCipher`
message-level encryption `InProcessTransferTransport` uses — see
``docs/adr/0017-tcp-transfer-transport.md`` for why that means no
separate TLS layer is required for this to be genuinely secure, and
for the connection-pooling and reconnect-logic this adapter
deliberately leaves for later.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import struct
from collections.abc import AsyncIterator
from typing import Any

import structlog
from cryptography.exceptions import InvalidTag

from securesync.core.protocol import Packet, PacketType, ProtocolError, make_header
from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.domain.conflict import VersionVector
from securesync.domain.crypto import NONCE_SIZE, TAG_SIZE, AeadCipher, EncryptedPayload
from securesync.domain.networking import Peer
from securesync.domain.transfer import IncomingPush, TransferTransport
from securesync.infrastructure.networking.message_io import (
    _LENGTH_PREFIX_FORMAT,
    INBOX_MAX_SIZE,
    MAX_CONCURRENT_CONNECTIONS,
    MAX_MESSAGE_SIZE,
    read_length_prefixed,
)
from securesync.infrastructure.networking.session_key_store import SessionKeyStore

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
        session_keys: SessionKeyStore,
    ) -> None:
        """Initialize the transport.

        Args:
            own_device_id: This device's ID — used as associated data
                to authenticate decryption of inbound messages.
            listen_host: Host/interface to accept inbound connections on.
            listen_port: Port to accept inbound connections on.
            cipher: The AEAD cipher used to encrypt and decrypt every message.
            session_keys: Per-peer `(send_key, receive_key)` registry,
                populated as
                :class:`~securesync.infrastructure.networking.x25519_handshake.X25519Handshake`
                handshakes complete — see
                ``docs/adr/0020-multi-peer-session-keys-and-main-py-wiring.md``.
        """
        self._own_device_id = own_device_id
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._cipher = cipher
        self._session_keys = session_keys
        self._message_id = 0
        self._inbox: asyncio.Queue[bytes] = asyncio.Queue(maxsize=INBOX_MAX_SIZE)
        self._active_connections = 0
        self._server: asyncio.Server | None = None

    def _next_message_id(self) -> int:
        """Return a monotonically increasing ID for request/response correlation."""
        self._message_id += 1
        return self._message_id

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
        """Read one encrypted envelope from an inbound connection and queue it.

        Each connection carries exactly one envelope — matching
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
            envelope = await self._read_envelope(reader)
            self._try_enqueue(envelope)
        except (
            asyncio.IncompleteReadError,
            ConnectionError,
            ProtocolError,
        ) as e:
            logger.warning("tcp_transport_connection_dropped", error=str(e))
        finally:
            self._active_connections -= 1
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    def _try_enqueue(self, envelope: bytes) -> None:
        """Add an envelope to the inbox, dropping it when the inbox is full."""
        try:
            self._inbox.put_nowait(envelope)
        except asyncio.QueueFull:
            logger.warning("inbox_full_dropping_envelope", maxsize=INBOX_MAX_SIZE)

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
        header = make_header(PacketType.CHUNK_DATA, message_id=self._next_message_id())
        framed = Packet(header=header, payload=payload).encode()

        nonce = os.urandom(NONCE_SIZE)
        # SessionKeyStore is always populated keyed by the *other*
        # side's device_id (see X25519SessionCoordinator.ensure_session
        # and main.py's _drain_inbound_handshakes, both of which call
        # `session_keys.put(result.peer_device_id, ...)`), so the
        # lookup here must use `peer.device_id`, not our own — looking
        # ourselves up here would only coincidentally work if we ever
        # had a peer whose device_id equaled our own, which never
        # happens in practice, so this silently failed on every real
        # multi-peer send until this fix.
        own_session = self._session_keys.get(peer.device_id)
        encrypted = self._cipher.encrypt(
            framed, own_session.send_key, nonce, associated_data=peer.device_id.encode("utf-8")
        )
        envelope = self._pack_envelope(encrypted)

        reader, writer = await asyncio.open_connection(
            peer.address.ip_address, own_session.transfer_port
        )
        try:
            writer.write(struct.pack(_LENGTH_PREFIX_FORMAT, len(envelope)) + envelope)
            await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()
        logger.info("chunk_sent_tcp", peer=peer.device_id, chunk_id=chunk.metadata.chunk_id)

    async def request_chunks(self, peer: Peer, chunk_hashes: list[str]) -> AsyncIterator[Chunk]:
        """Yield chunks received from `peer`, matching ``chunk_hashes``.

        Args:
            peer: The peer these chunks are expected to have come
                from — its negotiated `receive_key` is looked up from
                the session key store to decrypt them.
            chunk_hashes: The hex digests of the chunks to wait for.

        Yields:
            Each matching :class:`Chunk`, decrypted and reconstructed,
            as it arrives.

        Raises:
            NoSessionKeyError: If no handshake has completed for `peer` yet.
        """
        remaining = set(chunk_hashes)
        # Same fix as `send_chunk` above: the store is keyed by the
        # peer's device_id, not our own.
        own_session = self._session_keys.get(peer.device_id)
        while remaining:
            envelope = await self._inbox.get()
            encrypted = self._unpack_envelope(envelope)
            framed = self._cipher.decrypt(
                encrypted,
                own_session.receive_key,
                associated_data=self._own_device_id.encode("utf-8"),
            )
            packet = Packet.decode(framed)
            digest = packet.payload.get("hash_digest")
            if digest not in remaining:
                logger.warning("unrequested_chunk_dropped", digest=digest)
                continue
            remaining.discard(digest)
            yield self._chunk_from_payload(packet.payload)

    async def receive_pushes(self) -> AsyncIterator[IncomingPush]:
        """See :meth:`TransferTransport.receive_pushes`.

        Unlike `request_chunks`, this doesn't know in advance which
        peer a given message came from, so it tries every currently
        known session's `receive_key` in turn (AEAD authentication
        naturally rejects the wrong key, so this both decrypts and
        identifies the sender in one step) — practical for the small
        peer counts a P2P sync tool actually has.
        """
        while True:
            envelope = await self._inbox.get()
            encrypted = self._unpack_envelope(envelope)
            framed: bytes | None = None
            for session in self._session_keys.all_sessions():
                try:
                    framed = self._cipher.decrypt(
                        encrypted,
                        session.receive_key,
                        associated_data=self._own_device_id.encode("utf-8"),
                    )
                    break
                except InvalidTag:
                    continue
            if framed is None:
                logger.warning("undecryptable_push_dropped")
                continue
            packet = Packet.decode(framed)
            version_counters = packet.payload.get("version_counters")
            yield IncomingPush(
                relative_path=str(packet.payload["relative_path"]),
                total_chunks=int(packet.payload["total_chunks"]),
                chunk=self._chunk_from_payload(packet.payload),
                version_vector=(
                    VersionVector(dict(version_counters)) if version_counters is not None else None
                ),
            )

    @staticmethod
    async def _read_envelope(reader: asyncio.StreamReader) -> bytes:
        """Read one length-prefixed envelope from a stream."""
        return await read_length_prefixed(reader, max_size=MAX_MESSAGE_SIZE)

    @staticmethod
    def _pack_envelope(payload: EncryptedPayload) -> bytes:
        """Frame an `EncryptedPayload` as `nonce + tag + ciphertext`."""
        return payload.nonce + payload.tag + payload.ciphertext

    @staticmethod
    def _unpack_envelope(envelope: bytes) -> EncryptedPayload:
        """Reverse :meth:`_pack_envelope`."""
        nonce, tag, ciphertext = (
            envelope[:NONCE_SIZE],
            envelope[NONCE_SIZE : NONCE_SIZE + TAG_SIZE],
            envelope[NONCE_SIZE + TAG_SIZE :],
        )
        return EncryptedPayload(ciphertext=ciphertext, nonce=nonce, tag=tag)

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
