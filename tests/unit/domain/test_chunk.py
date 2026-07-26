"""Unit tests for `securesync.domain.chunk`."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from securesync.domain.chunk import (
    Chunk,
    ChunkAlgorithm,
    ChunkCollection,
    ChunkHash,
    ChunkMetadata,
)


class TestChunkAlgorithm:
    """Tests for the `ChunkAlgorithm` enum."""

    def test_sha256_value(self) -> None:
        """`SHA256`'s value is the lowercase algorithm name."""
        assert ChunkAlgorithm.SHA256.value == "sha256"

    def test_members_are_unique(self) -> None:
        """The `@unique` decorator guarantees no aliasing."""
        assert len(set(ChunkAlgorithm)) == len(list(ChunkAlgorithm))


class TestChunkHash:
    """Tests for `ChunkHash` construction and validation."""

    VALID_DIGEST = "a" * 64

    def test_valid_sha256_hash_constructs(self) -> None:
        """A 64-character hex digest is accepted for SHA-256."""
        chunk_hash = ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=self.VALID_DIGEST)
        assert chunk_hash.digest == self.VALID_DIGEST

    def test_empty_digest_rejected(self) -> None:
        """An empty digest raises ValueError."""
        with pytest.raises(ValueError, match="must not be empty"):
            ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest="")

    def test_non_hex_digest_rejected(self) -> None:
        """A digest containing non-hex characters raises ValueError."""
        with pytest.raises(ValueError, match="not valid hexadecimal"):
            ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest="z" * 64)

    def test_wrong_length_digest_rejected(self) -> None:
        """A digest of the wrong length for its algorithm raises ValueError."""
        with pytest.raises(ValueError, match="must be 64 hex characters"):
            ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest="ab")

    def test_str_renders_algorithm_and_digest(self) -> None:
        """`str()` renders as `algorithm:digest`."""
        chunk_hash = ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=self.VALID_DIGEST)
        assert str(chunk_hash) == f"sha256:{self.VALID_DIGEST}"

    def test_equal_hashes_compare_equal(self) -> None:
        """Two hashes with the same algorithm and digest are equal (value semantics)."""
        first = ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=self.VALID_DIGEST)
        second = ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=self.VALID_DIGEST)
        assert first == second

    def test_is_immutable(self) -> None:
        """A frozen dataclass rejects attribute assignment."""
        chunk_hash = ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=self.VALID_DIGEST)
        with pytest.raises(AttributeError):
            chunk_hash.digest = "b" * 64  # type: ignore[misc]


class TestChunkMetadata:
    """Tests for `ChunkMetadata` construction, validation, and `with_hash`."""

    def _make_hash(self) -> ChunkHash:
        return ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest="a" * 64)

    def test_constructs_with_required_fields(self) -> None:
        """Metadata constructs with an unset hash by default."""
        metadata = ChunkMetadata(chunk_id="chunk-0", index=0, size=4096, offset=0)
        assert metadata.chunk_hash is None
        assert isinstance(metadata.created_at, datetime)
        assert metadata.created_at.tzinfo is UTC

    def test_empty_chunk_id_rejected(self) -> None:
        """An empty `chunk_id` raises ValueError."""
        with pytest.raises(ValueError, match="chunk_id must not be empty"):
            ChunkMetadata(chunk_id="", index=0, size=0, offset=0)

    @pytest.mark.parametrize(
        ("field_name", "value"),
        [("index", -1), ("size", -1), ("offset", -1)],
    )
    def test_negative_numeric_fields_rejected(self, field_name: str, value: int) -> None:
        """A negative `index`, `size`, or `offset` raises ValueError."""
        kwargs = {"chunk_id": "chunk-0", "index": 0, "size": 0, "offset": 0}
        kwargs[field_name] = value
        with pytest.raises(ValueError, match=f"{field_name} must be >= 0"):
            ChunkMetadata(**kwargs)  # type: ignore[arg-type]

    def test_with_hash_returns_new_instance(self) -> None:
        """`with_hash` returns a new object; the original is unchanged."""
        original = ChunkMetadata(chunk_id="chunk-0", index=0, size=4, offset=0)
        chunk_hash = self._make_hash()
        updated = original.with_hash(chunk_hash)

        assert original.chunk_hash is None
        assert updated.chunk_hash == chunk_hash
        assert updated is not original
        assert updated.chunk_id == original.chunk_id

    def test_is_immutable(self) -> None:
        """A frozen dataclass rejects attribute assignment."""
        metadata = ChunkMetadata(chunk_id="chunk-0", index=0, size=0, offset=0)
        with pytest.raises(AttributeError):
            metadata.index = 1  # type: ignore[misc]


class TestChunk:
    """Tests for `Chunk` construction and validation."""

    def test_matching_size_constructs(self) -> None:
        """Data whose length matches `metadata.size` constructs cleanly."""
        metadata = ChunkMetadata(chunk_id="chunk-0", index=0, size=5, offset=0)
        chunk = Chunk(metadata=metadata, data=b"hello")
        assert chunk.data == b"hello"

    def test_mismatched_size_rejected(self) -> None:
        """Data whose length doesn't match `metadata.size` raises ValueError."""
        metadata = ChunkMetadata(chunk_id="chunk-0", index=0, size=10, offset=0)
        with pytest.raises(ValueError, match="does not match"):
            Chunk(metadata=metadata, data=b"short")

    def test_empty_data_matches_zero_size(self) -> None:
        """A zero-size chunk with empty data is valid."""
        metadata = ChunkMetadata(chunk_id="chunk-0", index=0, size=0, offset=0)
        chunk = Chunk(metadata=metadata, data=b"")
        assert chunk.data == b""

    def test_with_hash_preserves_data_and_updates_metadata(self) -> None:
        """`with_hash` updates only the metadata's hash, keeping data intact."""
        metadata = ChunkMetadata(chunk_id="chunk-0", index=0, size=5, offset=0)
        chunk = Chunk(metadata=metadata, data=b"hello")
        chunk_hash = ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest="a" * 64)

        updated = chunk.with_hash(chunk_hash)

        assert updated.data == b"hello"
        assert updated.metadata.chunk_hash == chunk_hash
        assert chunk.metadata.chunk_hash is None

    def test_is_immutable(self) -> None:
        """A frozen dataclass rejects attribute assignment."""
        metadata = ChunkMetadata(chunk_id="chunk-0", index=0, size=0, offset=0)
        chunk = Chunk(metadata=metadata, data=b"")
        with pytest.raises(AttributeError):
            chunk.data = b"x"  # type: ignore[misc]


class TestChunkCollection:
    """Tests for `ChunkCollection` construction and structural validation."""

    def _metadata(self, index: int, size: int, offset: int) -> ChunkMetadata:
        return ChunkMetadata(chunk_id=f"chunk-{index}", index=index, size=size, offset=offset)

    def test_empty_collection_is_valid(self) -> None:
        """An empty file has zero chunks and zero total size."""
        collection = ChunkCollection(
            source_path=Path("/data/empty.bin"), chunk_size=4096, total_size=0, chunks=()
        )
        assert collection.chunk_count == 0

    def test_contiguous_chunks_are_valid(self) -> None:
        """Chunks indexed 0..N-1 with sizes summing to total_size are valid."""
        chunks = (self._metadata(0, 4, 0), self._metadata(1, 4, 4), self._metadata(2, 2, 8))
        collection = ChunkCollection(
            source_path=Path("/data/file.bin"), chunk_size=4, total_size=10, chunks=chunks
        )
        assert collection.chunk_count == 3

    def test_non_positive_chunk_size_rejected(self) -> None:
        """A zero or negative `chunk_size` raises ValueError."""
        with pytest.raises(ValueError, match="chunk_size must be > 0"):
            ChunkCollection(source_path=Path("f"), chunk_size=0, total_size=0, chunks=())

    def test_negative_total_size_rejected(self) -> None:
        """A negative `total_size` raises ValueError."""
        with pytest.raises(ValueError, match="total_size must be >= 0"):
            ChunkCollection(source_path=Path("f"), chunk_size=4, total_size=-1, chunks=())

    def test_non_contiguous_indices_rejected(self) -> None:
        """Chunks with a gap or out-of-order index raise ValueError."""
        chunks = (self._metadata(0, 4, 0), self._metadata(2, 4, 4))
        with pytest.raises(ValueError, match="contiguously indexed"):
            ChunkCollection(source_path=Path("f"), chunk_size=4, total_size=8, chunks=chunks)

    def test_size_mismatch_rejected(self) -> None:
        """A `total_size` that doesn't match the sum of chunk sizes raises ValueError."""
        chunks = (self._metadata(0, 4, 0),)
        with pytest.raises(ValueError, match="does not match"):
            ChunkCollection(source_path=Path("f"), chunk_size=4, total_size=999, chunks=chunks)

    def test_is_immutable(self) -> None:
        """A frozen dataclass rejects attribute assignment."""
        collection = ChunkCollection(source_path=Path("f"), chunk_size=4, total_size=0, chunks=())
        with pytest.raises(AttributeError):
            collection.total_size = 1  # type: ignore[misc]
