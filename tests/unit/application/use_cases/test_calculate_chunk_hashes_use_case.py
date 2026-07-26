"""Unit tests for `CalculateChunkHashesUseCase`."""

from __future__ import annotations

from pathlib import Path

from securesync.application.use_cases.calculate_chunk_hashes import CalculateChunkHashesUseCase
from securesync.domain.chunk import Chunk, ChunkMetadata
from securesync.infrastructure.chunking.streaming_chunk_reader import FixedSizeChunkingStrategy
from tests.doubles import FakeChunkHasher, FakeChunkReader


def _chunk(index: int, data: bytes) -> Chunk:
    metadata = ChunkMetadata(
        chunk_id=f"chunk-{index}", index=index, size=len(data), offset=index * 4
    )
    return Chunk(metadata=metadata, data=data)


class TestExecute:
    """Tests for `CalculateChunkHashesUseCase.execute`."""

    async def test_yields_hashed_metadata_for_every_chunk(self) -> None:
        """Every chunk the reader produces yields exactly one hashed metadata record."""
        chunks = [_chunk(0, b"1234"), _chunk(1, b"5678")]
        use_case = CalculateChunkHashesUseCase(
            reader=FakeChunkReader(chunks), hasher=FakeChunkHasher()
        )

        results = [
            metadata
            async for metadata in use_case.execute(Path("/f.bin"), FixedSizeChunkingStrategy())
        ]

        assert [metadata.index for metadata in results] == [0, 1]
        assert all(metadata.chunk_hash is not None for metadata in results)

    async def test_never_exposes_chunk_bytes(self) -> None:
        """The hasher sees each chunk's bytes, but they never reach the caller."""
        hasher = FakeChunkHasher()
        use_case = CalculateChunkHashesUseCase(
            reader=FakeChunkReader([_chunk(0, b"secret-bytes")]), hasher=hasher
        )

        results = [
            metadata
            async for metadata in use_case.execute(Path("/f.bin"), FixedSizeChunkingStrategy())
        ]

        assert hasher.calls == [b"secret-bytes"]
        assert not hasattr(results[0], "data")


class TestBuildManifest:
    """Tests for `CalculateChunkHashesUseCase.build_manifest`."""

    async def test_returns_a_complete_collection(self) -> None:
        """The resulting manifest carries every chunk's hashed metadata."""
        chunks = [_chunk(0, b"1234"), _chunk(1, b"56")]
        use_case = CalculateChunkHashesUseCase(
            reader=FakeChunkReader(chunks), hasher=FakeChunkHasher()
        )

        manifest = await use_case.build_manifest(
            Path("/f.bin"), FixedSizeChunkingStrategy(chunk_size=4), chunk_size=4
        )

        assert manifest.chunk_count == 2
        assert manifest.total_size == 6
        assert manifest.chunk_size == 4
        assert manifest.source_path == Path("/f.bin")

    async def test_empty_source_yields_empty_manifest(self) -> None:
        """An empty file's manifest has zero chunks and zero total size."""
        use_case = CalculateChunkHashesUseCase(reader=FakeChunkReader([]), hasher=FakeChunkHasher())

        manifest = await use_case.build_manifest(
            Path("/empty.bin"), FixedSizeChunkingStrategy(), chunk_size=4 * 1024 * 1024
        )

        assert manifest.chunk_count == 0
        assert manifest.total_size == 0
