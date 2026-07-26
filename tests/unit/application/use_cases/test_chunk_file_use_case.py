"""Unit tests for `securesync.application.use_cases.chunk_file.ChunkFileUseCase`."""

from __future__ import annotations

from pathlib import Path

import pytest

from securesync.application.use_cases.chunk_file import ChunkFileUseCase
from securesync.domain.chunk import Chunk, ChunkMetadata
from securesync.domain.chunk_exceptions import ChunkSourceNotFoundError
from securesync.infrastructure.chunking.streaming_chunk_reader import FixedSizeChunkingStrategy
from tests.doubles import FakeChunkHasher, FakeChunkReader


def _chunk(index: int, data: bytes) -> Chunk:
    metadata = ChunkMetadata(chunk_id=f"chunk-{index}", index=index, size=len(data), offset=0)
    return Chunk(metadata=metadata, data=data)


class TestExecute:
    """Tests for `ChunkFileUseCase.execute`."""

    async def test_yields_every_chunk_from_the_reader(self) -> None:
        """Every chunk the reader produces is yielded back, in order."""
        chunks = [_chunk(0, b"1234"), _chunk(1, b"5678"), _chunk(2, b"90")]
        use_case = ChunkFileUseCase(reader=FakeChunkReader(chunks), hasher=FakeChunkHasher())

        results = [
            chunk
            async for chunk in use_case.execute(Path("/data/f.bin"), FixedSizeChunkingStrategy())
        ]

        assert [chunk.data for chunk in results] == [b"1234", b"5678", b"90"]

    async def test_every_yielded_chunk_is_hashed(self) -> None:
        """Each chunk crossing the use case boundary carries a populated hash."""
        reader = FakeChunkReader([_chunk(0, b"data")])
        hasher = FakeChunkHasher()
        use_case = ChunkFileUseCase(reader=reader, hasher=hasher)

        results = [
            chunk async for chunk in use_case.execute(Path("/f.bin"), FixedSizeChunkingStrategy())
        ]

        assert results[0].metadata.chunk_hash is not None
        assert hasher.calls == [b"data"]

    async def test_empty_file_yields_no_chunks(self) -> None:
        """An empty source (no chunks from the reader) yields nothing."""
        use_case = ChunkFileUseCase(reader=FakeChunkReader([]), hasher=FakeChunkHasher())
        results = [
            chunk
            async for chunk in use_case.execute(Path("/empty.bin"), FixedSizeChunkingStrategy())
        ]
        assert results == []

    async def test_passes_path_and_strategy_through_to_the_reader(self) -> None:
        """The reader receives exactly the path and strategy the caller supplied."""
        reader = FakeChunkReader([])
        use_case = ChunkFileUseCase(reader=reader, hasher=FakeChunkHasher())
        strategy = FixedSizeChunkingStrategy(chunk_size=1024)
        path = Path("/data/specific.bin")

        _ = [chunk async for chunk in use_case.execute(path, strategy)]

        assert reader.calls == [(path, strategy)]

    async def test_propagates_reader_errors(self) -> None:
        """An error from the reader propagates to the caller unchanged."""
        reader = FakeChunkReader([])
        reader.raise_on_read = ChunkSourceNotFoundError("missing")
        use_case = ChunkFileUseCase(reader=reader, hasher=FakeChunkHasher())

        with pytest.raises(ChunkSourceNotFoundError):
            _ = [
                chunk
                async for chunk in use_case.execute(
                    Path("/missing.bin"), FixedSizeChunkingStrategy()
                )
            ]

    async def test_original_chunk_data_is_preserved_after_hashing(self) -> None:
        """Hashing doesn't mutate or replace the chunk's bytes."""
        reader = FakeChunkReader([_chunk(0, b"exact-bytes")])
        use_case = ChunkFileUseCase(reader=reader, hasher=FakeChunkHasher())

        [result] = [
            chunk async for chunk in use_case.execute(Path("/f.bin"), FixedSizeChunkingStrategy())
        ]

        assert result.data == b"exact-bytes"
