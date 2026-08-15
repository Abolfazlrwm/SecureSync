"""In-process, encrypted implementation of the TransferTransport port.

Real TCP/TLS transport (accepting connections, framing over a socket)
is a separate, larger undertaking not yet built — see
``docs/adr/0016-in-process-encrypted-transport.md``. This adapter
fills the gap honestly rather than with a mock: it moves
:class:`~securesync.domain.chunk.Chunk` objects between two peers in
the same process through :class:`~securesync.domain.crypto.AeadCipher`
encryption and the real :mod:`securesync.core.protocol` wire framing
(CRC-checked, msgpack-encoded), so
:class:`~securesync.application.use_cases.transfer_chunks.UploadChunksUseCase`
and
:class:`~securesync.application.use_cases.transfer_chunks.DownloadChunksUseCase`
run against a genuinely working implementation of the port they
depend on — useful for same-process peer pairs and as the tested
foundation a future socket-based transport can wrap.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from typing import Any

import structlog

from securesync.core.protocol import Packet, PacketType, make_header
from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.domain.crypto import NONCE_SIZE, TAG_SIZE, AeadCipher, EncryptedPayload
from securesync.domain.networking import Peer
from securesync.domain.transfer import TransferTransport

logger = structlog.get_logger(__name__)


class InProcessNetwork:
    """A shared rendezvous point for `InProcessTransferTransport` instances.

    Holds one inbox queue per device ID. Two transports that share the
    same `InProcessNetwork` instance can reach each other by device ID,
    the same way two sockets on the same host can reach each other by
    port — this is the in-process stand-in for that addressing.
    """

    def __init__(self) -> None:
        """Initialize an empty network with no inboxes yet."""
        self._inboxes: dict[str, asyncio.Queue[bytes]] = {}

    def inbox_for(self, device_id: str) -> asyncio.Queue[bytes]:
        """Get (creating if necessary) the inbox queue for a device ID.

        Args:
            device_id: The device ID whose inbox to return.

        Returns:
            The `asyncio.Queue` of raw encrypted-and-framed messages
            addressed to that device.
        """
        if device_id not in self._inboxes:
            self._inboxes[device_id] = asyncio.Queue()
        return self._inboxes[device_id]


class InProcessTransferTransport(TransferTransport):
    """Moves chunks between peers in-process, encrypted with a real AEAD cipher.

    `send_chunk` serializes a chunk with :mod:`securesync.core.protocol`
    (real CRC-checked framing), encrypts the framed bytes, and enqueues
    them on the *recipient's* inbox. `request_chunks` reads from *this*
    device's own inbox — chunks arrive there because some other
    `InProcessTransferTransport` sharing the same `InProcessNetwork`
    called `send_chunk` addressed to this device.
    """

    def __init__(
        self,
        own_device_id: str,
        network: InProcessNetwork,
        cipher: AeadCipher,
        send_key: bytes,
        receive_key: bytes,
    ) -> None:
        """Initialize the transport.

        Args:
            own_device_id: This device's ID — the inbox `request_chunks` reads from.
            network: The shared network this transport sends and receives through.
            cipher: The AEAD cipher used to encrypt and decrypt every message.
            send_key: Key used to encrypt outgoing chunks in `send_chunk`.
            receive_key: Key used to decrypt incoming chunks in
                `request_chunks`. Must differ from `send_key` — see
                ``docs/adr/0018-key-exchange-handshake.md`` for why a
                single shared key was replaced with a directional pair.
        """
        self._own_device_id = own_device_id
        self._network = network
        self._cipher = cipher
        self._send_key = send_key
        self._receive_key = receive_key
        self._message_id = 0

    def _next_message_id(self) -> int:
        """Return a monotonically increasing ID for request/response correlation."""
        self._message_id += 1
        return self._message_id

    async def send_chunk(self, peer: Peer, chunk: Chunk) -> None:
        """Encrypt and deliver a chunk to a peer's inbox.

        Args:
            peer: The peer to send the chunk to.
            chunk: The chunk to send.
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
        }
        header = make_header(PacketType.CHUNK_DATA, message_id=self._next_message_id())
        framed = Packet(header=header, payload=payload).encode()

        nonce = os.urandom(NONCE_SIZE)
        encrypted = self._cipher.encrypt(
            framed, self._send_key, nonce, associated_data=peer.device_id.encode("utf-8")
        )
        await self._network.inbox_for(peer.device_id).put(self._pack_envelope(encrypted))
        logger.info("chunk_sent", peer=peer.device_id, chunk_id=chunk.metadata.chunk_id)

    async def request_chunks(self, peer: Peer, chunk_hashes: list[str]) -> AsyncIterator[Chunk]:
        """Yield chunks addressed to this device by ``peer``, matching ``chunk_hashes``.

        Args:
            peer: The peer these chunks are expected to have come from
                (used only to derive the associated data that
                authenticates decryption — this transport doesn't
                verify the sender's identity beyond that).
            chunk_hashes: The hex digests of the chunks to wait for.
                Messages that decrypt correctly but don't match any
                requested hash are dropped with a warning; this
                transport has no separate request/response round trip,
                only a shared inbox.

        Yields:
            Each matching :class:`Chunk`, decrypted and reconstructed,
            as it arrives.
        """
        remaining = set(chunk_hashes)
        inbox = self._network.inbox_for(self._own_device_id)
        while remaining:
            envelope = await inbox.get()
            encrypted = self._unpack_envelope(envelope)
            framed = self._cipher.decrypt(
                encrypted, self._receive_key, associated_data=self._own_device_id.encode("utf-8")
            )
            packet = Packet.decode(framed)
            digest = packet.payload.get("hash_digest")
            if digest not in remaining:
                logger.warning("unrequested_chunk_dropped", digest=digest, peer=peer.device_id)
                continue
            remaining.discard(digest)
            yield self._chunk_from_payload(packet.payload)

    @staticmethod
    def _pack_envelope(payload: EncryptedPayload) -> bytes:
        """Frame an `EncryptedPayload` as `nonce + tag + ciphertext` for the inbox queue."""
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
