"""Unit tests for `securesync.infrastructure.chunking.streaming_chunk_reader.StreamingChunkReader`.

Covers correctness of the chunk-boundary loop itself (offsets, indices,
sizes, chunk IDs) using small, fast, in-process files. Larger,
real-world-scale scenarios (huge files, random binary content, Unicode
filenames) live in ``tests/chunking/`` alongside the rest of the
project's real-filesystem test suite.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from securesync.domain.chunk_exceptions import (
    ChunkingError,
    ChunkSourceAccessError,
    ChunkSourceNotFoundError,
)
from securesync.domain.chunking import ChunkingStrategy
from securesync.infrastructure.chunking.streaming_chunk_reader import (
    FixedSizeChunkingStrategy,
    StreamingChunkReader,
    _derive_chunk_id,
    _read_full,
)
from tests.platform import running_as_root


@pytest.fixture
def reader() -> StreamingChunkReader:
    """A fresh `StreamingChunkReader` for each test."""
    return StreamingChunkReader()


class TestMissingOrInvalidSource:
    """Tests for the reader's handling of a source that can't be read."""

    def test_nonexistent_file_raises_not_found(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A path that doesn't exist raises `ChunkSourceNotFoundError`."""
        missing = tmp_path / "does_not_exist.bin"
        with pytest.raises(ChunkSourceNotFoundError):
            list(reader.read_chunks(missing, FixedSizeChunkingStrategy()))

    def test_directory_raises_access_error(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A directory (not a regular file) raises `ChunkSourceAccessError`."""
        with pytest.raises(ChunkSourceAccessError):
            list(reader.read_chunks(tmp_path, FixedSizeChunkingStrategy()))

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits don't apply on Windows")
    @pytest.mark.skipif(running_as_root(), reason="root bypasses permission checks")
    def test_permission_denied_raises_access_error(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A file without read permission raises `ChunkSourceAccessError`."""
        target = tmp_path / "no_access.bin"
        target.write_bytes(b"secret")
        target.chmod(0o000)
        try:
            with pytest.raises(ChunkSourceAccessError):
                list(reader.read_chunks(target, FixedSizeChunkingStrategy()))
        finally:
            target.chmod(0o644)  # restore so tmp_path cleanup can remove it


class TestChunkBoundaries:
    """Tests for the reader's chunk boundaries, sizes, offsets, and indices."""

    def test_empty_file_yields_no_chunks(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """An empty file produces zero chunks."""
        target = tmp_path / "empty.bin"
        target.write_bytes(b"")
        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=4)))
        assert chunks == []

    def test_one_byte_file_yields_single_short_chunk(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A 1-byte file smaller than the chunk size yields one short chunk."""
        target = tmp_path / "one_byte.bin"
        target.write_bytes(b"x")
        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=4)))
        assert len(chunks) == 1
        assert chunks[0].data == b"x"
        assert chunks[0].metadata.size == 1
        assert chunks[0].metadata.offset == 0
        assert chunks[0].metadata.index == 0

    def test_two_byte_file_yields_single_short_chunk(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A 2-byte file smaller than the chunk size yields one short chunk."""
        target = tmp_path / "two_bytes.bin"
        target.write_bytes(b"xy")
        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=4)))
        assert len(chunks) == 1
        assert chunks[0].data == b"xy"

    def test_file_exactly_one_chunk_size_yields_one_full_chunk(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A file exactly one chunk in size yields exactly one chunk (no empty trailer)."""
        target = tmp_path / "exact.bin"
        target.write_bytes(b"1234")
        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=4)))
        assert len(chunks) == 1
        assert chunks[0].data == b"1234"

    def test_file_exactly_multiple_chunk_sizes_yields_no_empty_trailer(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A file that's an exact multiple of chunk_size has no trailing empty chunk."""
        target = tmp_path / "exact_multiple.bin"
        target.write_bytes(b"1234" * 5)  # exactly 5 chunks of size 4
        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=4)))
        assert len(chunks) == 5
        assert all(chunk.metadata.size == 4 for chunk in chunks)

    def test_multiple_chunks_with_short_final_chunk(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A file not evenly divisible by chunk_size has a shorter final chunk."""
        target = tmp_path / "multi.bin"
        target.write_bytes(b"1234567890")  # 10 bytes, chunk_size 4 -> 4,4,2
        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=4)))
        sizes = [chunk.metadata.size for chunk in chunks]
        assert sizes == [4, 4, 2]

    def test_chunk_indices_and_offsets_are_contiguous(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """Indices start at 0 and increment; offsets track cumulative size."""
        target = tmp_path / "multi.bin"
        target.write_bytes(b"1234567890")
        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=4)))
        assert [chunk.metadata.index for chunk in chunks] == [0, 1, 2]
        assert [chunk.metadata.offset for chunk in chunks] == [0, 4, 8]

    def test_reconstructed_data_matches_original(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """Concatenating every chunk's data reproduces the original file byte-for-byte."""
        original = bytes(range(256)) * 10  # 2560 bytes, deterministic pseudo-random-ish content
        target = tmp_path / "roundtrip.bin"
        target.write_bytes(original)
        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=97)))
        assert b"".join(chunk.data for chunk in chunks) == original

    def test_chunk_size_larger_than_file_yields_one_chunk(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A chunk size far larger than the file still yields exactly one chunk."""
        target = tmp_path / "small.bin"
        target.write_bytes(b"tiny")
        chunks = list(
            reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=10 * 1024 * 1024))
        )
        assert len(chunks) == 1
        assert chunks[0].data == b"tiny"

    def test_chunk_size_of_one_yields_one_chunk_per_byte(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A chunk size of 1 produces one chunk per byte."""
        target = tmp_path / "small.bin"
        target.write_bytes(b"abc")
        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=1)))
        assert [chunk.data for chunk in chunks] == [b"a", b"b", b"c"]

    def test_chunks_are_unhashed(self, reader: StreamingChunkReader, tmp_path: Path) -> None:
        """`StreamingChunkReader` never computes a hash — that's `ChunkHasher`'s job."""
        target = tmp_path / "file.bin"
        target.write_bytes(b"1234")
        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=4)))
        assert chunks[0].metadata.chunk_hash is None


class TestChunkIds:
    """Tests for chunk ID derivation."""

    def test_chunk_ids_are_deterministic(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """Re-reading the same file with the same strategy reproduces identical chunk IDs."""
        target = tmp_path / "file.bin"
        target.write_bytes(b"1234567890")
        first_pass = [
            c.metadata.chunk_id
            for c in reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=4))
        ]
        second_pass = [
            c.metadata.chunk_id
            for c in reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=4))
        ]
        assert first_pass == second_pass

    def test_different_indices_get_different_ids(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """Chunks at different indices of the same file get different IDs."""
        target = tmp_path / "file.bin"
        target.write_bytes(b"1234567890")
        chunks = list(reader.read_chunks(target, FixedSizeChunkingStrategy(chunk_size=4)))
        ids = [chunk.metadata.chunk_id for chunk in chunks]
        assert len(ids) == len(set(ids))

    def test_derive_chunk_id_is_a_stable_uuid_string(self) -> None:
        """`_derive_chunk_id` returns the same UUID string for the same inputs."""
        first = _derive_chunk_id(Path("/data/file.bin"), 0)
        second = _derive_chunk_id(Path("/data/file.bin"), 0)
        assert first == second
        assert _derive_chunk_id(Path("/data/file.bin"), 1) != first

    def test_identical_content_at_different_paths_gets_different_chunk_ids(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """`chunk_id` is local to a path; identical content elsewhere gets a different one.

        Locks in the distinction documented on `ChunkMetadata.chunk_id`:
        it is not a content-addressable identifier — that's
        `chunk_hash`'s job (SHA256HashProvider, tested separately) —
        so two files with byte-identical content but different paths
        must never collide on `chunk_id`.
        """
        content = b"identical content"
        first_path = tmp_path / "a" / "file.bin"
        second_path = tmp_path / "b" / "file.bin"
        first_path.parent.mkdir()
        second_path.parent.mkdir()
        first_path.write_bytes(content)
        second_path.write_bytes(content)

        [first_chunk] = list(reader.read_chunks(first_path, FixedSizeChunkingStrategy()))
        [second_chunk] = list(reader.read_chunks(second_path, FixedSizeChunkingStrategy()))

        assert first_chunk.metadata.chunk_id != second_chunk.metadata.chunk_id
        assert first_chunk.data == second_chunk.data


class _RejectAllStrategy(ChunkingStrategy):
    """Test-only strategy that always returns an invalid (non-positive) cut."""

    @property
    def name(self) -> str:
        return "reject-all"

    def next_cut(self, buffered: memoryview, *, at_eof: bool) -> int | None:
        if len(buffered) > 0:
            return 0  # invalid: a real strategy must never return <= 0
        return None


class TestDefensiveGuards:
    """Tests for the reader's defensive handling of a misbehaving strategy."""

    def test_non_positive_cut_point_raises_chunking_error(
        self, reader: StreamingChunkReader, tmp_path: Path
    ) -> None:
        """A strategy returning a non-positive cut point is rejected, not looped forever."""
        target = tmp_path / "file.bin"
        target.write_bytes(b"1234")
        with pytest.raises(ChunkingError, match="non-positive cut point"):
            list(reader.read_chunks(target, _RejectAllStrategy()))


class _PartialReadFile:
    """Test double for a binary file object whose `readinto` returns short reads.

    Simulates the POSIX behavior `_read_full` is written to tolerate:
    a single `readinto()` call may return fewer bytes than requested,
    even mid-file, not only at EOF.
    """

    def __init__(self, data: bytes, max_read_size: int) -> None:
        self._data = data
        self._max_read_size = max_read_size
        self._position = 0

    def readinto(self, view: memoryview) -> int:
        n = min(len(view), self._max_read_size, len(self._data) - self._position)
        view[:n] = self._data[self._position : self._position + n]
        self._position += n
        return n


class TestReadFull:
    """Tests for the `_read_full` short-read-tolerant helper."""

    def test_fills_buffer_in_one_call_when_possible(self) -> None:
        """A file that never short-reads fills the buffer in one pass."""
        file = _PartialReadFile(b"1234567890", max_read_size=100)
        buffer = bytearray(10)
        assert _read_full(file, buffer) == 10
        assert bytes(buffer) == b"1234567890"

    def test_loops_through_short_reads_to_fill_buffer(self) -> None:
        """Multiple short `readinto` calls are transparently stitched together."""
        file = _PartialReadFile(b"1234567890", max_read_size=3)
        buffer = bytearray(10)
        assert _read_full(file, buffer) == 10
        assert bytes(buffer) == b"1234567890"

    def test_returns_fewer_bytes_than_requested_at_genuine_eof(self) -> None:
        """If the source runs out mid-buffer, only the bytes actually read are counted."""
        file = _PartialReadFile(b"123", max_read_size=100)
        buffer = bytearray(10)
        assert _read_full(file, buffer) == 3
        assert bytes(buffer[:3]) == b"123"

    def test_returns_zero_for_already_exhausted_source(self) -> None:
        """Calling again after EOF returns 0, not an error."""
        file = _PartialReadFile(b"", max_read_size=100)
        buffer = bytearray(10)
        assert _read_full(file, buffer) == 0
