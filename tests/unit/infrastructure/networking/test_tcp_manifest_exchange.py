"""Unit tests for TcpManifestExchangeTransport."""

from __future__ import annotations

from pathlib import Path

from securesync.domain.chunk import ChunkAlgorithm, ChunkCollection, ChunkHash, ChunkMetadata
from securesync.domain.networking import Peer, PeerAddress, PeerCapabilities, PeerIdentity
from securesync.infrastructure.chunking.file_chunk_repository import FileChunkRepository
from securesync.infrastructure.crypto.pyca_crypto import AesGcmCipher
from securesync.infrastructure.networking.session_key_store import PeerSession, SessionKeyStore
from securesync.infrastructure.networking.tcp_manifest_exchange import (
    TcpManifestExchangeTransport,
)

KEY_1 = b"1" * 32
KEY_2 = b"2" * 32


def _peer(device_id: str, port: int) -> Peer:
    return Peer(
        identity=PeerIdentity(device_id, f"host-{device_id}", f"fp-{device_id}"),
        address=PeerAddress("127.0.0.1", port),
        capabilities=PeerCapabilities("1.0"),
    )


def _collection(source_path: str) -> ChunkCollection:
    return ChunkCollection(
        source_path=Path(source_path),
        chunk_size=4,
        total_size=4,
        chunks=(ChunkMetadata("c1", 0, 4, 0, ChunkHash(ChunkAlgorithm.SHA256, "a" * 64)),),
    )


def _paired_transports(
    tmp_path: Path, port_a: int, port_b: int
) -> tuple[TcpManifestExchangeTransport, TcpManifestExchangeTransport]:
    cipher = AesGcmCipher()
    session_keys_a, session_keys_b = SessionKeyStore(), SessionKeyStore()
    session_keys_a.put("dev-b", PeerSession(KEY_1, KEY_2, transfer_port=0, manifest_port=port_b))
    session_keys_b.put("dev-a", PeerSession(KEY_2, KEY_1, transfer_port=0, manifest_port=port_a))
    repo_a = FileChunkRepository(storage_dir=tmp_path / "a")
    repo_b = FileChunkRepository(storage_dir=tmp_path / "b")
    transport_a = TcpManifestExchangeTransport(
        "dev-a", "127.0.0.1", port_a, cipher, session_keys_a, repo_a
    )
    transport_b = TcpManifestExchangeTransport(
        "dev-b", "127.0.0.1", port_b, cipher, session_keys_b, repo_b
    )
    return transport_a, transport_b


class TestRequestManifest:
    """Tests for requesting a peer's manifest over a real socket."""

    async def test_receives_the_peers_real_manifest(self, tmp_path: Path) -> None:
        transport_a, transport_b = _paired_transports(tmp_path, 19401, 19402)
        # B has a manifest for "shared.txt"; A does not.
        FileChunkRepository(storage_dir=tmp_path / "b").save(_collection("shared.txt"))
        await transport_a.start()
        await transport_b.start()
        try:
            result = await transport_a.request_manifest(_peer("dev-b", 19402), "shared.txt")

            assert result is not None
            assert result.chunks[0].chunk_hash is not None
            assert result.chunks[0].chunk_hash.digest == "a" * 64
        finally:
            await transport_a.stop()
            await transport_b.stop()

    async def test_returns_none_for_a_file_the_peer_does_not_have(self, tmp_path: Path) -> None:
        transport_a, transport_b = _paired_transports(tmp_path, 19403, 19404)
        await transport_a.start()
        await transport_b.start()
        try:
            result = await transport_a.request_manifest(_peer("dev-b", 19404), "missing.txt")

            assert result is None
        finally:
            await transport_a.stop()
            await transport_b.stop()

    async def test_bidirectional_manifest_requests(self, tmp_path: Path) -> None:
        """Each side can both serve and request manifests over its own socket."""
        transport_a, transport_b = _paired_transports(tmp_path, 19405, 19406)
        FileChunkRepository(storage_dir=tmp_path / "a").save(_collection("a-file.txt"))
        FileChunkRepository(storage_dir=tmp_path / "b").save(_collection("b-file.txt"))
        await transport_a.start()
        await transport_b.start()
        try:
            from_b = await transport_a.request_manifest(_peer("dev-b", 19406), "b-file.txt")
            from_a = await transport_b.request_manifest(_peer("dev-a", 19405), "a-file.txt")

            assert from_b is not None
            assert from_a is not None
        finally:
            await transport_a.stop()
            await transport_b.stop()
