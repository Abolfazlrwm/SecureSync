"""Real TCP implementation of the ManifestExchangeTransport port.

Unlike :class:`~securesync.infrastructure.networking.tcp_transport.TcpTransferTransport`
(fire-and-forget: push a chunk, addressee reads it whenever), this is
a true request/response exchange over one connection: the requester
sends an encrypted request and waits on the same connection for an
encrypted response, since a manifest lookup needs an answer, not just
delivery. Reuses the already-negotiated
:class:`~securesync.infrastructure.networking.session_store.PeerSession`
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
import struct
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Protocol

import msgpack  # type: ignore[import-untyped]
import structlog

from securesync.core.protocol import PacketType, ProtocolError
from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.domain.chunking import ChunkRepository
from securesync.domain.conflict import VersionVector
from securesync.domain.crypto import AeadCipher
from securesync.domain.manifest_exchange import (
    ManifestExchangeTransport,
    ManifestWithVersion,
)
from securesync.domain.networking import Peer
from securesync.infrastructure.chunking.file_chunk_repository import (
    collection_from_dict,
    collection_to_dict,
)
from securesync.infrastructure.networking.message_io import (
    _LENGTH_PREFIX_FORMAT,
    MAX_CONCURRENT_CONNECTIONS,
    MAX_MESSAGE_SIZE,
    read_length_prefixed,
)
from securesync.infrastructure.networking.replay_protection import ReplayProtectionError
from securesync.infrastructure.networking.secure_channel import SecureChannel
from securesync.infrastructure.networking.session_store import NoSessionError, SessionStore
from securesync.shared.safe_path import UnsafePathError, resolve_within

logger = structlog.get_logger(__name__)


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
        sessions: SessionStore,
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
            sessions: Negotiated sessions, shared with whatever
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
        self._sessions = sessions
        self._channel = SecureChannel(own_device_id, cipher, sessions)
        self._chunk_repository = chunk_repository
        self._sync_root = sync_root
        self._metadata_lookup = metadata_lookup
        self._active_connections = 0
        self._server: asyncio.Server | None = None

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
            NoSessionError: If the peer has no confirmed session.
            OSError: If `peer` can't be reached.
        """
        session = self._sessions.get_send_session(peer.device_id)
        if session is None:
            raise NoSessionError(
                f"no confirmed session for {peer.device_id!r} — a handshake must complete first"
            )
        frame = self._channel.seal(
            session, PacketType.FILE_MANIFEST, {"relative_path": relative_path}
        )

        reader, writer = await asyncio.open_connection(
            peer.address.ip_address, session.manifest_port
        )
        try:
            await self._write_message(writer, {"envelope": frame})
            response = await self._read_message(reader)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

        response_packet, _ = self._channel.open(response["envelope"])
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
            NoSessionError: If the peer has no confirmed session.
            OSError: If `peer` can't be reached.
        """
        session = self._sessions.get_send_session(peer.device_id)
        if session is None:
            raise NoSessionError(
                f"no confirmed session for {peer.device_id!r} — a handshake must complete first"
            )
        payload = {"relative_path": relative_path, "chunk_hashes": chunk_hashes}
        frame = self._channel.seal(session, PacketType.CHUNK_REQUEST, payload)

        reader, writer = await asyncio.open_connection(
            peer.address.ip_address, session.manifest_port
        )
        try:
            await self._write_message(writer, {"envelope": frame})
            response = await self._read_message(reader)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

        response_packet, _ = self._channel.open(response["envelope"])
        for chunk_payload in response_packet.payload["chunks"]:
            yield self._chunk_from_payload(chunk_payload)

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Answer one inbound manifest or chunk-data request on its own connection."""
        if self._active_connections >= MAX_CONCURRENT_CONNECTIONS:
            logger.warning("manifest_refused_too_many", active=self._active_connections)
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()
            return

        self._active_connections += 1
        try:
            request = await self._read_message(reader)
            # The session comes from the frame's authenticated session_id, not
            # from any device_id the requester claims.
            request_packet, session = self._channel.open(request["envelope"])

            if request_packet.header.packet_type == PacketType.CHUNK_REQUEST:
                response_payload = self._build_chunk_response(request_packet.payload)
                response_type = PacketType.CHUNK_DATA
            else:
                response_payload = await self._build_manifest_response(request_packet.payload)
                response_type = PacketType.FILE_MANIFEST

            response_frame = self._channel.seal(session, response_type, response_payload)
            await self._write_message(writer, {"envelope": response_frame})
        except (
            asyncio.IncompleteReadError,
            ConnectionError,
            KeyError,
            ProtocolError,
            ReplayProtectionError,
        ) as e:
            logger.warning("manifest_exchange_request_failed", error=str(e))
        except UnsafePathError as e:
            # A peer asked for a path outside our sync root. Dropping
            # the connection (rather than answering) is the whole point:
            # the request never reaches the chunk repository.
            logger.warning("manifest_exchange_path_rejected", error=str(e))
        finally:
            self._active_connections -= 1
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
        data = await read_length_prefixed(reader, max_size=MAX_MESSAGE_SIZE)
        result: dict[str, Any] = msgpack.unpackb(data, raw=False)
        return result

    def _safe_resolve(self, relative_path: str) -> Path:
        """Resolve a peer-supplied relative path against the sync root.

        Delegates to :func:`~securesync.shared.safe_path.resolve_within`
        so this transport and the push receiver enforce exactly the same
        rules. This previously used a ``str.startswith`` prefix
        comparison, which is both weaker than it looks (``/srv/sync-evil``
        passes a check against ``/srv/sync``) and inconsistent with the
        push path, which had no check at all.

        Raises:
            UnsafePathError: If the path would resolve outside the sync root.
        """
        return resolve_within(self._sync_root, relative_path)
