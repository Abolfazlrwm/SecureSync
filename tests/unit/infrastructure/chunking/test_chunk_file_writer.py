"""Unit tests for `securesync.infrastructure.chunking.chunk_file_writer.ChunkFileWriter`."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from securesync.domain.chunk import Chunk, ChunkMetadata
from securesync.infrastructure.chunking.chunk_file_writer import ChunkFileWriter
from securesync.shared.exceptions import ChunkEngineError
from tests.platform import running_as_root


def _make_chunk(data: bytes = b"hello", chunk_id: str = "chunk-0") -> Chunk:
    metadata = ChunkMetadata(chunk_id=chunk_id, index=0, size=len(data), offset=0)
    return Chunk(metadata=metadata, data=data)


@pytest.fixture
def writer() -> ChunkFileWriter:
    """A fresh `ChunkFileWriter` for each test."""
    return ChunkFileWriter()


class TestWriteChunk:
    """Tests for `ChunkFileWriter.write_chunk`."""

    def test_writes_chunk_bytes_to_destination(
        self, writer: ChunkFileWriter, tmp_path: Path
    ) -> None:
        """The destination file's content matches the chunk's data exactly."""
        destination = tmp_path / "chunk-0.bin"
        writer.write_chunk(destination, _make_chunk(b"payload"))
        assert destination.read_bytes() == b"payload"

    def test_creates_missing_parent_directories(
        self, writer: ChunkFileWriter, tmp_path: Path
    ) -> None:
        """Nested parent directories are created automatically."""
        destination = tmp_path / "nested" / "deeper" / "chunk-0.bin"
        writer.write_chunk(destination, _make_chunk(b"data"))
        assert destination.read_bytes() == b"data"

    def test_overwrites_existing_destination(self, writer: ChunkFileWriter, tmp_path: Path) -> None:
        """Writing to an existing path replaces its content."""
        destination = tmp_path / "chunk-0.bin"
        destination.write_bytes(b"old content")
        writer.write_chunk(destination, _make_chunk(b"new"))
        assert destination.read_bytes() == b"new"

    def test_writes_empty_chunk(self, writer: ChunkFileWriter, tmp_path: Path) -> None:
        """A zero-byte chunk writes an empty file, not an error."""
        destination = tmp_path / "empty.bin"
        writer.write_chunk(destination, _make_chunk(b""))
        assert destination.read_bytes() == b""

    def test_no_leftover_temp_file_after_successful_write(
        self, writer: ChunkFileWriter, tmp_path: Path
    ) -> None:
        """A successful write leaves only the final destination file behind."""
        destination = tmp_path / "chunk-0.bin"
        writer.write_chunk(destination, _make_chunk(b"data"))
        assert list(tmp_path.iterdir()) == [destination]

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits don't apply on Windows")
    @pytest.mark.skipif(running_as_root(), reason="root bypasses permission checks")
    def test_write_failure_raises_chunk_engine_error_and_cleans_up_temp_file(
        self, writer: ChunkFileWriter, tmp_path: Path
    ) -> None:
        """A write that fails raises `ChunkEngineError` and removes its temp file."""
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        destination = readonly_dir / "chunk-0.bin"
        readonly_dir.chmod(0o555)
        try:
            with pytest.raises(ChunkEngineError):
                writer.write_chunk(destination, _make_chunk(b"data"))
        finally:
            readonly_dir.chmod(0o755)
        assert list(readonly_dir.iterdir()) == []

    def test_write_failure_error_chains_original_cause(
        self, writer: ChunkFileWriter, tmp_path: Path
    ) -> None:
        """The raised `ChunkEngineError` preserves the original `OSError` as its cause."""
        # A destination whose parent is actually a file (not a directory) can
        # never be created, regardless of permissions or platform.
        blocking_file = tmp_path / "not_a_directory"
        blocking_file.write_bytes(b"x")
        destination = blocking_file / "chunk-0.bin"

        with pytest.raises(ChunkEngineError) as exc_info:
            writer.write_chunk(destination, _make_chunk(b"data"))
        assert isinstance(exc_info.value.__cause__, OSError)
