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


def _write_and_save(root: Path, relative_path: str, data: bytes, repo: FileChunkRepository) -> None:
    """Write real bytes at `root / relative_path` and save a matching one-chunk manifest."""
    local_path = root / relative_path
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(data)
    collection = ChunkCollection(
        source_path=local_path,
        chunk_size=len(data),
        total_size=len(data),
        chunks=(ChunkMetadata("c1", 0, len(data), 0, ChunkHash(ChunkAlgorithm.SHA256, "a" * 64)),),
    )
    repo.save(collection)


def _paired_transports(
    tmp_path: Path, port_a: int, port_b: int
) -> tuple[TcpManifestExchangeTransport, TcpManifestExchangeTransport, Path, Path]:
    cipher = AesGcmCipher()
    session_keys_a, session_keys_b = SessionKeyStore(), SessionKeyStore()
    session_keys_a.put("dev-b", PeerSession(KEY_1, KEY_2, transfer_port=0, manifest_port=port_b))
    session_keys_b.put("dev-a", PeerSession(KEY_2, KEY_1, transfer_port=0, manifest_port=port_a))
    sync_root_a, sync_root_b = tmp_path / "root-a", tmp_path / "root-b"
    sync_root_a.mkdir()
    sync_root_b.mkdir()
    repo_a = FileChunkRepository(storage_dir=tmp_path / "manifests-a")
    repo_b = FileChunkRepository(storage_dir=tmp_path / "manifests-b")
    transport_a = TcpManifestExchangeTransport(
        "dev-a", "127.0.0.1", port_a, cipher, session_keys_a, repo_a, sync_root_a
    )
    transport_b = TcpManifestExchangeTransport(
        "dev-b", "127.0.0.1", port_b, cipher, session_keys_b, repo_b, sync_root_b
    )
    return transport_a, transport_b, sync_root_a, sync_root_b


class TestRequestManifest:
    """Tests for requesting a peer's manifest over a real socket."""

    async def test_receives_the_peers_real_manifest(self, tmp_path: Path) -> None:
        transport_a, transport_b, root_a, root_b = _paired_transports(tmp_path, 19401, 19402)
        repo_b = FileChunkRepository(storage_dir=tmp_path / "manifests-b")
        _write_and_save(root_b, "shared.txt", b"data", repo_b)
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
        transport_a, transport_b, _, _ = _paired_transports(tmp_path, 19403, 19404)
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
        transport_a, transport_b, root_a, root_b = _paired_transports(tmp_path, 19405, 19406)
        repo_a = FileChunkRepository(storage_dir=tmp_path / "manifests-a")
        repo_b = FileChunkRepository(storage_dir=tmp_path / "manifests-b")
        _write_and_save(root_a, "a-file.txt", b"data", repo_a)
        _write_and_save(root_b, "b-file.txt", b"data", repo_b)
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


class TestRequestChunks:
    """Tests for pulling specific chunks' real bytes from a peer."""

    async def test_receives_the_peers_real_chunk_bytes(self, tmp_path: Path) -> None:
        transport_a, transport_b, root_a, root_b = _paired_transports(tmp_path, 19407, 19408)
        repo_b = FileChunkRepository(storage_dir=tmp_path / "manifests-b")
        _write_and_save(root_b, "shared.txt", b"hello!", repo_b)
        await transport_a.start()
        await transport_b.start()
        try:
            chunks = [
                c
                async for c in transport_a.request_chunks(
                    _peer("dev-b", 19408), "shared.txt", ["a" * 64]
                )
            ]

            assert len(chunks) == 1
            assert chunks[0].data == b"hello!"
        finally:
            await transport_a.stop()
            await transport_b.stop()

    async def test_omits_hashes_the_peer_does_not_have(self, tmp_path: Path) -> None:
        transport_a, transport_b, root_a, root_b = _paired_transports(tmp_path, 19409, 19410)
        repo_b = FileChunkRepository(storage_dir=tmp_path / "manifests-b")
        _write_and_save(root_b, "shared.txt", b"hello!", repo_b)
        await transport_a.start()
        await transport_b.start()
        try:
            chunks = [
                c
                async for c in transport_a.request_chunks(
                    _peer("dev-b", 19410), "shared.txt", ["a" * 64, "b" * 64]
                )
            ]

            assert len(chunks) == 1
        finally:
            await transport_a.stop()
            await transport_b.stop()
