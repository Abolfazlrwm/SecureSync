"""Unit tests for SyncFileUseCase."""

from __future__ import annotations

from pathlib import Path

from securesync.application.use_cases.calculate_chunk_hashes import CalculateChunkHashesUseCase
from securesync.application.use_cases.chunk_file import ChunkFileUseCase
from securesync.application.use_cases.sync_file import SyncFileUseCase
from securesync.application.use_cases.transfer_chunks import UploadChunksUseCase
from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkCollection, ChunkHash, ChunkMetadata
from securesync.domain.networking import Peer, PeerAddress, PeerCapabilities, PeerIdentity
from securesync.infrastructure.chunking.local_file_reconstructor import LocalFileReconstructor
from securesync.infrastructure.chunking.sha256_hash_provider import SHA256HashProvider
from securesync.infrastructure.chunking.streaming_chunk_reader import (
    FixedSizeChunkingStrategy,
    StreamingChunkReader,
)
from tests.doubles import FakeChunkRepository, FakeManifestExchangeTransport, FakeTransferTransport


def _peer(device_id: str) -> Peer:
    return Peer(
        identity=PeerIdentity(device_id, f"host-{device_id}", f"fp-{device_id}"),
        address=PeerAddress("127.0.0.1", 9000),
        capabilities=PeerCapabilities("1.0"),
    )


def _use_case(
    manifest_exchange: FakeManifestExchangeTransport,
    transport: FakeTransferTransport,
    chunk_repository: FakeChunkRepository,
) -> SyncFileUseCase:
    reader, hasher = StreamingChunkReader(), SHA256HashProvider()
    return SyncFileUseCase(
        manifest_exchange,
        ChunkFileUseCase(reader, hasher),
        CalculateChunkHashesUseCase(reader, hasher),
        UploadChunksUseCase(transport),
        chunk_repository,
        LocalFileReconstructor(),
    )


class TestPush:
    """Tests for SyncFileUseCase.push."""

    async def test_uploads_everything_when_peer_has_nothing(self, tmp_path: Path) -> None:
        sync_root = tmp_path / "root"
        sync_root.mkdir()
        (sync_root / "f.txt").write_bytes(b"hello world!")
        transport = FakeTransferTransport()
        use_case = _use_case(FakeManifestExchangeTransport(), transport, FakeChunkRepository())

        strategy = FixedSizeChunkingStrategy(chunk_size=4)
        result = await use_case.push(_peer("dev-b"), sync_root, "f.txt", strategy, chunk_size=4)

        assert result.transferred_count == len(transport.sent)
        assert result.transferred_count > 0

    async def test_uploads_nothing_when_peer_already_has_everything(self, tmp_path: Path) -> None:
        sync_root = tmp_path / "root"
        sync_root.mkdir()
        source_path = sync_root / "f.txt"
        source_path.write_bytes(b"hello world!")
        strategy = FixedSizeChunkingStrategy(chunk_size=4)

        # Build the real manifest for this file, then seed it as what the peer already has.
        calc = CalculateChunkHashesUseCase(StreamingChunkReader(), SHA256HashProvider())
        current = await calc.build_manifest(source_path, strategy, chunk_size=4)
        manifest_exchange = FakeManifestExchangeTransport()
        manifest_exchange.manifests[("dev-b", "f.txt")] = current
        transport = FakeTransferTransport()
        use_case = _use_case(manifest_exchange, transport, FakeChunkRepository())

        result = await use_case.push(_peer("dev-b"), sync_root, "f.txt", strategy, chunk_size=4)

        assert result.transferred_count == 0
        assert transport.sent == []

    async def test_saves_the_local_manifest_as_the_new_baseline(self, tmp_path: Path) -> None:
        sync_root = tmp_path / "root"
        sync_root.mkdir()
        (sync_root / "f.txt").write_bytes(b"hello world!")
        chunk_repository = FakeChunkRepository()
        use_case = _use_case(
            FakeManifestExchangeTransport(), FakeTransferTransport(), chunk_repository
        )

        strategy = FixedSizeChunkingStrategy(chunk_size=4)
        await use_case.push(_peer("dev-b"), sync_root, "f.txt", strategy, chunk_size=4)

        assert chunk_repository.save_calls == 1


class TestPull:
    """Tests for SyncFileUseCase.pull."""

    async def test_returns_zero_when_peer_has_no_manifest(self, tmp_path: Path) -> None:
        sync_root = tmp_path / "root"
        sync_root.mkdir()
        use_case = _use_case(
            FakeManifestExchangeTransport(), FakeTransferTransport(), FakeChunkRepository()
        )

        strategy = FixedSizeChunkingStrategy(chunk_size=4)
        result = await use_case.pull(_peer("dev-b"), sync_root, "f.txt", strategy, chunk_size=4)

        assert result.transferred_count == 0

    async def test_downloads_and_writes_missing_content(self, tmp_path: Path) -> None:
        sync_root = tmp_path / "root"
        sync_root.mkdir()
        destination = sync_root / "f.txt"  # does not exist locally yet
        chunk_hash = ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest="a" * 64)
        metadata = ChunkMetadata("c1", 0, 4, 0, chunk_hash)
        peer_collection = ChunkCollection(
            source_path=Path("irrelevant"), chunk_size=4, total_size=4, chunks=(metadata,)
        )
        manifest_exchange = FakeManifestExchangeTransport()
        manifest_exchange.manifests[("dev-b", "f.txt")] = peer_collection
        manifest_exchange.chunks[("dev-b", "f.txt")] = [Chunk(metadata=metadata, data=b"data")]
        use_case = _use_case(manifest_exchange, FakeTransferTransport(), FakeChunkRepository())

        strategy = FixedSizeChunkingStrategy(chunk_size=4)
        result = await use_case.pull(_peer("dev-b"), sync_root, "f.txt", strategy, chunk_size=4)

        assert result.transferred_count == 1
        assert destination.read_bytes() == b"data"

    async def test_never_uploads_anything(self, tmp_path: Path) -> None:
        """pull() must not touch the transport at all — it only receives."""
        sync_root = tmp_path / "root"
        sync_root.mkdir()
        chunk_hash = ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest="a" * 64)
        metadata = ChunkMetadata("c1", 0, 4, 0, chunk_hash)
        peer_collection = ChunkCollection(
            source_path=Path("irrelevant"), chunk_size=4, total_size=4, chunks=(metadata,)
        )
        manifest_exchange = FakeManifestExchangeTransport()
        manifest_exchange.manifests[("dev-b", "f.txt")] = peer_collection
        manifest_exchange.chunks[("dev-b", "f.txt")] = [Chunk(metadata=metadata, data=b"data")]
        transport = FakeTransferTransport()
        use_case = _use_case(manifest_exchange, transport, FakeChunkRepository())

        strategy = FixedSizeChunkingStrategy(chunk_size=4)
        await use_case.pull(_peer("dev-b"), sync_root, "f.txt", strategy, chunk_size=4)

        assert transport.sent == []
