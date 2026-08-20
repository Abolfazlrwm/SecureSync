"""Unit tests for LocalFileReconstructor."""

from __future__ import annotations

from pathlib import Path

from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.infrastructure.chunking.local_file_reconstructor import LocalFileReconstructor


def _chunk(index: int, offset: int, data: bytes, digest: str) -> Chunk:
    metadata = ChunkMetadata(
        chunk_id=f"c{index}",
        index=index,
        size=len(data),
        offset=offset,
        chunk_hash=ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=digest),
    )
    return Chunk(metadata=metadata, data=data)


class TestWriteChunkAtOffset:
    """Tests for writing chunks into their correct position in a target file."""

    def test_creates_a_new_file(self, tmp_path: Path) -> None:
        destination = tmp_path / "out.bin"
        LocalFileReconstructor().write_chunk_at_offset(destination, _chunk(0, 0, b"AAAA", "a" * 64))

        assert destination.read_bytes() == b"AAAA"

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        destination = tmp_path / "nested" / "dir" / "out.bin"
        LocalFileReconstructor().write_chunk_at_offset(destination, _chunk(0, 0, b"AAAA", "a" * 64))

        assert destination.exists()

    def test_chunks_written_out_of_order_reassemble_correctly(self, tmp_path: Path) -> None:
        destination = tmp_path / "out.bin"
        reconstructor = LocalFileReconstructor()

        reconstructor.write_chunk_at_offset(destination, _chunk(1, 4, b"BBBB", "b" * 64))
        reconstructor.write_chunk_at_offset(destination, _chunk(0, 0, b"AAAA", "a" * 64))

        assert destination.read_bytes() == b"AAAABBBB"

    def test_overwriting_one_chunk_does_not_disturb_others(self, tmp_path: Path) -> None:
        destination = tmp_path / "out.bin"
        reconstructor = LocalFileReconstructor()
        reconstructor.write_chunk_at_offset(destination, _chunk(0, 0, b"AAAA", "a" * 64))
        reconstructor.write_chunk_at_offset(destination, _chunk(1, 4, b"BBBB", "b" * 64))

        reconstructor.write_chunk_at_offset(destination, _chunk(1, 4, b"CCCC", "c" * 64))

        assert destination.read_bytes() == b"AAAACCCC"
