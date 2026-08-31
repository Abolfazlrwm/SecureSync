"""Real TCP implementation of the ManifestExchangeTransport port.

Unlike :class:`~securesync.infrastructure.networking.tcp_transport.TcpTransferTransport`
(fire-and-forget: push a chunk, addressee reads it whenever), this is
a true request/response exchange over one connection: the requester
sends an encrypted request and waits on the same connection for an
encrypted response, since a manifest lookup needs an answer, not just
delivery. Reuses the already-negotiated
:class:`~securesync.infrastructure.networking.session_key_store.PeerSession`
keys from the same handshake `TcpTransferTransport` uses — no separate
key exchange for this port.

Phase 17: the response now includes the file's `VersionVector`
alongside its `ChunkCollection`, so the caller can decide
push/pull/conflict/noop without re-querying. The version comes from a
`MetadataRepository` (SQLite-backed in production); if none is
configured the returned version is `None` and the caller falls back
to content-hash-only diffing. See
``docs/adr/0024-version-aware-sync-direction.md``.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import struct
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Protocol

import msgpack  # type: ignore[import-untyped]
import structlog

from securesync.core.protocol import Packet, PacketType, make_header
from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.domain.chunking import ChunkRepository
from securesync.domain.conflict import VersionVector
from securesync.domain.crypto import NONCE_SIZE, TAG_SIZE, AeadCipher, EncryptedPayload
from securesync.domain.manifest_exchange import (
    ManifestExchangeTransport,
    ManifestWithVersion,
)
from securesync.domain.networking import Peer
from securesync.infrastructure.chunking.file_chunk_repository import (
    collection_from_dict,
    collection_to_dict,
)
from securesync.infrastructure.networking.session_key_store import SessionKeyStore

logger = structlog.get_logger(__name__)

_LENGTH_PREFIX_FORMAT = ">I"
_LENGTH_PREFIX_SIZE = struct.calcsize(_LENGTH_PREFIX_FORMAT)


class _MetadataLookup(Protocol):
    """Minimum MetadataRepository surface the manifest exchange needs.

    Kept narrow so callers can pass any object that exposes
    `get_file_metadata(relative_path) -> FileMetadata | None`. The
    full `MetadataRepository` ABC satisfies this naturally; defining
    it locally keeps this module's import surface independent of the
    metadata infrastructure layout.
    """

    async def get_file_metadata(self, file_path: str) -> Any:  # returns FileMetadata | None
        ...


class TcpManifestExchangeTransport(ManifestExchangeTransport):
    """Serves local chunk manifests to peers, and requests theirs, over real TCP."""

    def __init__(
        self,
        own_device_id: str,
        listen_host: str,
        listen_port: int,
        cipher: AeadCipher,
        session_keys: SessionKeyStore,
        chunk_repository: ChunkRepository,
        sync_root: Path,
        metadata_lookup: _MetadataLookup | None = None,
    ) -> None:
        """Initialize the transport.

        Args:
            own_device_id: This device's ID.
            listen_host: Host/interface to accept inbound requests on.
            listen_port: Port to accept inbound requests on.
            cipher: The AEAD cipher used to encrypt and decrypt every message.
            session_keys: Per-peer session keys, shared with whatever
                `TcpTransferTransport` negotiated them.
            chunk_repository: Local store manifests are served from
                when a peer requests one — the same port
                `ComputeDeltaUseCase` reads baselines from.
            sync_root: This device's local sync directory. Requests
                identify a file by a path *relative* to each side's
                own sync root (see
                ``docs/adr/0022-file-synchronization-use-case.md`` for
                why an absolute path can't be the shared identifier
                across two machines with different filesystem
                layouts) — `sync_root` is what turns that relative
                path back into this device's own absolute path before
                looking it up in `chunk_repository`.
            metadata_lookup: Optional metadata repository for resolving
                a file's `VersionVector`. When provided, manifest
                responses include the peer-side version vector so
                `SyncDirectionResolver` can decide push/pull/conflict
                without a second round trip. When ``None`` (legacy
                setups, tests) the version is reported as ``None``
                and the caller falls back to content-hash-only
                direction decisions.
        """
        self._own_device_id = own_device_id
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._cipher = cipher
        self._session_keys = session_keys
        self._chunk_repository = chunk_repository
        self._sync_root = sync_root
        self._metadata_lookup = metadata_lookup
        self._message_id = 0
        self._server: asyncio.Server | None = None

    def _next_message_id(self) -> int:
        """Return a monotonically increasing ID for request/response correlation."""
        self._message_id += 1
        return self._message_id

    async def start(self) -> None:
        """Start accepting inbound manifest requests.

        Raises:
            OSError: If `listen_port` can't be bound.
        """
        self._server = await asyncio.start_server(
            self._handle_connection, self._listen_host, self._listen_port
        )
        logger.info("manifest_exchange_started", host=self._listen_host, port=self._listen_port)

    async def stop(self) -> None:
        """Stop accepting inbound manifest requests."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info("manifest_exchange_stopped")

    async def request_manifest(self, peer: Peer, relative_path: str) -> ManifestWithVersion | None:
        """Request `peer`'s manifest + version for `relative_path`.

        Args:
            peer: The peer to request the manifest from.
            relative_path: The file to request a manifest for, as a
                path relative to each side's own sync root — never an
                absolute path, since the two peers' sync directories
                generally live at different absolute locations.

        Returns:
            A `ManifestWithVersion` carrying the peer's
            `ChunkCollection` and its `VersionVector`, or `None` if
            the peer doesn't have that file.

        Raises:
            OSError: If `peer` can't be reached.
        """
        session = self._session_keys.get(peer.device_id)
        header = make_header(PacketType.FILE_MANIFEST, message_id=self._next_message_id())
        framed = Packet(header=header, payload={"relative_path": relative_path}).encode()
        nonce = os.urandom(NONCE_SIZE)
        encrypted = self._cipher.encrypt(
            framed, session.send_key, nonce, associated_data=peer.device_id.encode("utf-8")
        )

        reader, writer = await asyncio.open_connection(
            peer.address.ip_address, session.manifest_port
        )
        try:
            envelope = self._pack_envelope(encrypted)
            await self._write_message(
                writer, {"device_id": self._own_device_id, "envelope": envelope}
            )
            response = await self._read_message(reader)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

        response_encrypted = self._unpack_envelope(response["envelope"])
        associated_data = self._own_device_id.encode("utf-8")
        response_framed = self._cipher.decrypt(
            response_encrypted, session.receive_key, associated_data=associated_data
        )
        response_packet = Packet.decode(response_framed)
        if not response_packet.payload["found"]:
            return None

        collection = collection_from_dict(response_packet.payload["collection"])
        # Peer reports its VersionVector as a counters dict (or None).
        version_payload = response_packet.payload.get("version")
        version = VersionVector(dict(version_payload["counters"])) if version_payload else None
        return ManifestWithVersion(collection=collection, version=version)

    async def request_chunks(
        self, peer: Peer, relative_path: str, chunk_hashes: list[str]
    ) -> AsyncIterator[Chunk]:
        """Request specific chunks' bytes for `relative_path` from `peer`, by hash.

        Args:
            peer: The peer to request chunks from.
            relative_path: The file the requested chunks belong to.
            chunk_hashes: The hex digests of the chunks to request.

        Yields:
            Each requested chunk the peer actually has, with real data.

        Raises:
            OSError: If `peer` can't be reached.
        """
        session = self._session_keys.get(peer.device_id)
        header = make_header(PacketType.CHUNK_REQUEST, message_id=self._next_message_id())
        payload = {"relative_path": relative_path, "chunk_hashes": chunk_hashes}
        framed = Packet(header=header, payload=payload).encode()
        nonce = os.urandom(NONCE_SIZE)
        encrypted = self._cipher.encrypt(
            framed, session.send_key, nonce, associated_data=peer.device_id.encode("utf-8")
        )

        reader, writer = await asyncio.open_connection(
            peer.address.ip_address, session.manifest_port
        )
        try:
            envelope = self._pack_envelope(encrypted)
            await self._write_message(
                writer, {"device_id": self._own_device_id, "envelope": envelope}
            )
            response = await self._read_message(reader)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

        response_encrypted = self._unpack_envelope(response["envelope"])
        associated_data = self._own_device_id.encode("utf-8")
        response_framed = self._cipher.decrypt(
            response_encrypted, session.receive_key, associated_data=associated_data
        )
        response_packet = Packet.decode(response_framed)
        for chunk_payload in response_packet.payload["chunks"]:
            yield self._chunk_from_payload(chunk_payload)

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Answer one inbound manifest or chunk-data request on its own connection."""
        try:
            request = await self._read_message(reader)
            session = self._session_keys.get(request["device_id"])
            request_encrypted = self._unpack_envelope(request["envelope"])
            request_framed = self._cipher.decrypt(
                request_encrypted,
                session.receive_key,
                associated_data=self._own_device_id.encode("utf-8"),
            )
            request_packet = Packet.decode(request_framed)

            if request_packet.header.packet_type == PacketType.CHUNK_REQUEST:
                response_payload = self._build_chunk_response(request_packet.payload)
                response_type = PacketType.CHUNK_DATA
            else:
                response_payload = await self._build_manifest_response(request_packet.payload)
                response_type = PacketType.FILE_MANIFEST

            response_header = make_header(response_type, message_id=self._next_message_id())
            response_framed = Packet(header=response_header, payload=response_payload).encode()
            nonce = os.urandom(NONCE_SIZE)
            response_encrypted = self._cipher.encrypt(
                response_framed,
                session.send_key,
                nonce,
                associated_data=request["device_id"].encode("utf-8"),
            )
            envelope = self._pack_envelope(response_encrypted)
            await self._write_message(writer, {"envelope": envelope})
        except (asyncio.IncompleteReadError, ConnectionError, KeyError) as e:
            logger.warning("manifest_exchange_request_failed", error=str(e))
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    async def _build_manifest_response(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        """Look up the requested file's manifest + version and build a response payload."""
        relative_path = request_payload["relative_path"]
        resolved = self._safe_resolve(relative_path)
        collection = self._chunk_repository.load(resolved)
        version = await self._resolve_version(relative_path)
        return {
            "found": collection is not None,
            "collection": collection_to_dict(collection) if collection is not None else None,
            # Version is included even when the chunk collection isn't found
            # — a peer may know the file's lineage without a manifest cached
            # yet, though in practice both are written together.
            "version": {"counters": version.counters} if version is not None else None,
        }

    async def _resolve_version(self, relative_path: str) -> VersionVector | None:
        """Look up the local VersionVector for `relative_path`.

        Returns None if no metadata lookup is configured, or if the
        metadata repository has no record for this file (e.g. a file
        that exists on disk but hasn't been seen by the orchestrator
        yet, or a peer that doesn't persist versions).
        """
        if self._metadata_lookup is None:
            return None
        meta = await self._metadata_lookup.get_file_metadata(relative_path)
        if meta is None:
            return None
        return getattr(meta, "version_vector", None)

    def _build_chunk_response(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        """Read the requested chunks' real bytes from the local file and build a response."""
        relative_path = request_payload["relative_path"]
        requested_hashes = set(request_payload["chunk_hashes"])
        local_path = self._safe_resolve(relative_path)
        collection = self._chunk_repository.load(local_path)

        chunks_payload: list[dict[str, Any]] = []
        if collection is not None:
            with local_path.open("rb") as file:
                for metadata in collection.chunks:
                    chunk_hash = metadata.chunk_hash
                    if chunk_hash is None or chunk_hash.digest not in requested_hashes:
                        continue
                    file.seek(metadata.offset)
                    data = file.read(metadata.size)
                    chunks_payload.append(
                        {
                            "chunk_id": metadata.chunk_id,
                            "index": metadata.index,
                            "size": metadata.size,
                            "offset": metadata.offset,
                            "hash_algorithm": chunk_hash.algorithm.value,
                            "hash_digest": chunk_hash.digest,
                            "data": data,
                        }
                    )
        return {"chunks": chunks_payload}

    @staticmethod
    def _chunk_from_payload(payload: dict[str, Any]) -> Chunk:
        """Reconstruct a `Chunk` from a decoded chunk-response payload entry."""
        metadata = ChunkMetadata(
            chunk_id=str(payload["chunk_id"]),
            index=int(payload["index"]),
            size=int(payload["size"]),
            offset=int(payload["offset"]),
            chunk_hash=ChunkHash(
                algorithm=ChunkAlgorithm(payload["hash_algorithm"]),
                digest=str(payload["hash_digest"]),
            ),
        )
        return Chunk(metadata=metadata, data=payload["data"])

    @staticmethod
    async def _write_message(writer: asyncio.StreamWriter, message: dict[str, Any]) -> None:
        """Write a length-prefixed, msgpack-encoded message."""
        data = msgpack.packb(message)
        writer.write(struct.pack(_LENGTH_PREFIX_FORMAT, len(data)) + data)
        await writer.drain()

    @staticmethod
    async def _read_message(reader: asyncio.StreamReader) -> dict[str, Any]:
        """Read and decode a length-prefixed, msgpack-encoded message."""
        length_bytes = await reader.readexactly(_LENGTH_PREFIX_SIZE)
        (length,) = struct.unpack(_LENGTH_PREFIX_FORMAT, length_bytes)
        data = await reader.readexactly(length)
        result: dict[str, Any] = msgpack.unpackb(data, raw=False)
        return result

    @staticmethod
    def _pack_envelope(payload: EncryptedPayload) -> bytes:
        """Frame an `EncryptedPayload` as `nonce + tag + ciphertext`."""
        return payload.nonce + payload.tag + payload.ciphertext

    def _safe_resolve(self, relative_path: str) -> Path:
        """Resolve a relative path against sync_root, rejecting path traversal."""
        resolved = (self._sync_root / relative_path).resolve()
        sync_root_resolved = self._sync_root.resolve()
        if not str(resolved).startswith(str(sync_root_resolved) + os.sep):
            raise ValueError(f"Path traversal rejected: {relative_path!r} escapes sync root")
        return resolved

    @staticmethod
    def _unpack_envelope(envelope: bytes) -> EncryptedPayload:
        """Reverse :meth:`_pack_envelope`."""
        nonce, tag, ciphertext = (
            envelope[:NONCE_SIZE],
            envelope[NONCE_SIZE : NONCE_SIZE + TAG_SIZE],
            envelope[NONCE_SIZE + TAG_SIZE :],
        )
        return EncryptedPayload(ciphertext=ciphertext, nonce=nonce, tag=tag)
