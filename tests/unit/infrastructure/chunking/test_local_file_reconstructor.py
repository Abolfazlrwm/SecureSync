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


class TestPartialLifecycle:
    """Tests for assembling a file in a temporary sibling, then committing it."""

    def test_begin_partial_returns_a_separate_file(self, tmp_path: Path) -> None:
        destination = tmp_path / "out.bin"

        partial = LocalFileReconstructor().begin_partial(destination)

        assert partial.exists()
        assert partial != destination
        assert partial.parent == destination.parent, "temp must be on the same filesystem"
        assert not destination.exists(), "the real path must not exist until commit"

    def test_begin_partial_seeds_from_the_existing_file(self, tmp_path: Path) -> None:
        """A delta push only sends changed chunks; the rest comes from the current file."""
        destination = tmp_path / "out.bin"
        destination.write_bytes(b"OLDCONTENT")

        partial = LocalFileReconstructor().begin_partial(destination)

        assert partial.read_bytes() == b"OLDCONTENT"

    def test_commit_moves_the_partial_into_place(self, tmp_path: Path) -> None:
        destination = tmp_path / "out.bin"
        destination.write_bytes(b"OLD")
        reconstructor = LocalFileReconstructor()
        partial = reconstructor.begin_partial(destination)
        reconstructor.write_chunk_at_offset(partial, _chunk(0, 0, b"NEW", "a" * 64))

        reconstructor.commit_partial(destination, partial)

        assert destination.read_bytes() == b"NEW"
        assert not partial.exists(), "the temporary file must not survive a commit"

    def test_abort_leaves_the_original_untouched(self, tmp_path: Path) -> None:
        destination = tmp_path / "out.bin"
        destination.write_bytes(b"OLD")
        reconstructor = LocalFileReconstructor()
        partial = reconstructor.begin_partial(destination)
        reconstructor.write_chunk_at_offset(partial, _chunk(0, 0, b"NEW", "a" * 64))

        reconstructor.abort_partial(partial)

        assert destination.read_bytes() == b"OLD"
        assert not partial.exists()

    def test_abort_is_idempotent(self, tmp_path: Path) -> None:
        """Cleanup runs on several paths; a second call must not raise."""
        reconstructor = LocalFileReconstructor()
        partial = reconstructor.begin_partial(tmp_path / "out.bin")

        reconstructor.abort_partial(partial)
        reconstructor.abort_partial(partial)

        assert not partial.exists()

    def test_partial_files_are_hidden_and_named_for_cleanup(self, tmp_path: Path) -> None:
        """Name shape matters: `*.part` is what leftover-cleanup tooling looks for."""
        partial = LocalFileReconstructor().begin_partial(tmp_path / "out.bin")

        assert partial.name.startswith(".")
        assert partial.suffix == ".part"
