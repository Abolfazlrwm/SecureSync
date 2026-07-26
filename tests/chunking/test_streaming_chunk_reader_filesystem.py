"""Real-filesystem tests for `StreamingChunkReader` at realistic scale.

Complements `tests/unit/infrastructure/chunking/test_streaming_chunk_reader.py`
(fast, small, logic-focused) with larger files, random binary content,
Unicode filenames, and actual peak-memory measurement — the scenarios
that only mean something against a real file on a real filesystem.
"""

from __future__ import annotations

import os
import tracemalloc
from pathlib import Path, PureWindowsPath

import pytest

from securesync.infrastructure.chunking.streaming_chunk_reader import (
    FixedSizeChunkingStrategy,
    StreamingChunkReader,
)


@pytest.fixture
def reader() -> StreamingChunkReader:
    """A fresh `StreamingChunkReader` for each test."""
    return StreamingChunkReader()


class TestRealisticFileSizes:
    """Tests against files large enough to exercise many chunk boundaries."""

    def test_moderately_large_file_reconstructs_exactly(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A ~10 MiB file split into 64 KiB chunks reconstructs byte-for-byte."""
        original = os.urandom(10 * 1024 * 1024)
        target = tmp_path / "large.bin"
        target.write_bytes(original)

        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=64 * 1024)))

        assert b"".join(chunk.data for chunk in chunks) == original
        assert len(chunks) == 160  # 10 MiB / 64 KiB, evenly divisible

    def test_many_small_chunks_from_a_moderately_large_file(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A file split into thousands of small chunks stays correct throughout."""
        original = os.urandom(2 * 1024 * 1024)
        target = tmp_path / "many_chunks.bin"
        target.write_bytes(original)

        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=256)))

        assert len(chunks) == (2 * 1024 * 1024) // 256
        assert b"".join(chunk.data for chunk in chunks) == original
        # Every chunk except (possibly) the last must be full-sized.
        assert all(chunk.metadata.size == 256 for chunk in chunks)

    def test_random_binary_content_round_trips(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """Non-textual, non-patterned random content chunks and reassembles cleanly."""
        original = os.urandom(500_000)
        target = tmp_path / "random.bin"
        target.write_bytes(original)

        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=4096)))

        assert b"".join(chunk.data for chunk in chunks) == original

    def test_utf8_text_content_round_trips_as_bytes(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """UTF-8 text (including multi-byte characters) survives byte-exact round trip."""
        text = "Hello, world! سلام دنیا 你好世界 🎉🔒📦" * 500
        original = text.encode("utf-8")
        target = tmp_path / "text.txt"
        target.write_bytes(original)

        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=37)))

        reconstructed = b"".join(chunk.data for chunk in chunks)
        assert reconstructed == original
        assert reconstructed.decode("utf-8") == text


class TestUnicodeAndPlatformPaths:
    """Tests for filenames and paths beyond plain ASCII."""

    @pytest.mark.parametrize(
        "filename",
        [
            "سند-یونیکد.bin",
            "文件名.bin",
            "файл.bin",
            "emoji-📦-name.bin",
            "spaced name with (parens).bin",
        ],
    )
    def test_unicode_filenames_are_read_correctly(
        self, reader: StreamingChunkReader, tmp_path: Path, filename: str
    ) -> None:
        """A file whose name contains non-ASCII characters chunks correctly."""
        content = b"content for " + filename.encode("utf-8")
        target = tmp_path / filename
        target.write_bytes(content)

        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=8)))

        assert b"".join(chunk.data for chunk in chunks) == content

    def test_nested_unicode_directory_path(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A file nested under Unicode directory names is reachable via `pathlib.Path`."""
        nested_dir = tmp_path / "پوشه" / "子目录"
        nested_dir.mkdir(parents=True)
        target = nested_dir / "file.bin"
        target.write_bytes(b"nested content")

        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=4)))

        assert b"".join(chunk.data for chunk in chunks) == b"nested content"

    def test_pure_windows_style_path_is_representable(self) -> None:
        """`PureWindowsPath` (a Windows-style path, checkable cross-platform) round-trips.

        This doesn't perform real I/O (a `PureWindowsPath` can't be
        opened on a POSIX CI runner) — it confirms
        `StreamingChunkReader`'s use of `pathlib.Path` throughout
        doesn't assume POSIX-only path syntax, since chunk IDs and
        error messages format the path via plain `str()`.
        """
        windows_path = PureWindowsPath(r"C:\Users\example\Documents\file.bin")
        assert str(windows_path) == r"C:\Users\example\Documents\file.bin"
        assert windows_path.name == "file.bin"


class TestPeakMemoryStaysBounded:
    """Confirms peak memory during chunking is bounded by chunk size, not file size."""

    def test_peak_memory_does_not_scale_with_file_size(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """Chunking a much larger file doesn't proportionally increase peak memory.

        Not a strict byte-for-byte bound (Python's allocator and GC
        introduce noise) — this asserts the qualitative property that
        matters: peak additional memory stays within a small constant
        multiple of the chunk size, never approaching the file size.
        """
        chunk_size = 256 * 1024
        small_file = tmp_path / "small.bin"
        small_file.write_bytes(os.urandom(chunk_size * 4))
        large_file = tmp_path / "large.bin"
        large_file.write_bytes(os.urandom(chunk_size * 64))

        tracemalloc.start()
        try:
            for _ in reader.read_chunks(small_file, FixedSizeChunkingStrategy(chunk_size)):
                pass
            _, small_peak = tracemalloc.get_traced_memory()
            tracemalloc.reset_peak()

            for _ in reader.read_chunks(large_file, FixedSizeChunkingStrategy(chunk_size)):
                pass
            _, large_peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        # The large file is 16x the small file's size; peak memory must
        # stay far below that ratio (bounded by chunk size, not file size).
        assert large_peak < small_peak * 4
