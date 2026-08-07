"""Unit tests for `securesync.domain.delta`."""

from __future__ import annotations

from pathlib import Path

import pytest

from securesync.domain.chunk import ChunkAlgorithm, ChunkCollection, ChunkHash, ChunkMetadata
from securesync.domain.delta import ChunkAction, DeltaCalculator
from securesync.domain.delta_exceptions import IncompatibleBaselineError, UnhashedChunkError


def _hash(label: str) -> ChunkHash:
    """Build a syntactically valid `ChunkHash` distinguishable by `label`."""
    return ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=label * 64)


def _metadata(index: int, *, size: int = 4, chunk_hash: ChunkHash | None) -> ChunkMetadata:
    return ChunkMetadata(
        chunk_id=f"chunk-{index}",
        index=index,
        size=size,
        offset=index * size,
        chunk_hash=chunk_hash,
    )


def _collection(path: Path, chunks: list[ChunkMetadata], *, chunk_size: int = 4) -> ChunkCollection:
    return ChunkCollection(
        source_path=path,
        chunk_size=chunk_size,
        total_size=sum(chunk.size for chunk in chunks),
        chunks=tuple(chunks),
    )


class TestComputeWithNoBaseline:
    """Tests for `DeltaCalculator.compute` on a file's first sync."""

    def test_every_chunk_must_be_transferred(self) -> None:
        """With no baseline, every current chunk is classified as `TRANSFER`."""
        path = Path("/f.bin")
        current = _collection(
            path, [_metadata(0, chunk_hash=_hash("a")), _metadata(1, chunk_hash=_hash("b"))]
        )

        plan = DeltaCalculator().compute(baseline=None, current=current)

        assert plan.is_first_sync is True
        assert plan.transfer_count == 2
        assert plan.reuse_count == 0
        assert all(entry.action is ChunkAction.TRANSFER for entry in plan.entries)

    def test_empty_file_has_no_changes(self) -> None:
        """An empty current manifest with no baseline has nothing to transfer."""
        path = Path("/empty.bin")
        current = _collection(path, [])

        plan = DeltaCalculator().compute(baseline=None, current=current)

        assert plan.has_changes is False
        assert plan.bytes_to_transfer == 0


class TestComputeWithBaseline:
    """Tests for `DeltaCalculator.compute` diffing against a prior manifest."""

    def test_identical_manifest_reuses_every_chunk(self) -> None:
        """An unchanged file reuses every chunk and has no changes."""
        path = Path("/f.bin")
        chunks = [_metadata(0, chunk_hash=_hash("a")), _metadata(1, chunk_hash=_hash("b"))]
        baseline = _collection(path, chunks)
        current = _collection(path, chunks)

        plan = DeltaCalculator().compute(baseline=baseline, current=current)

        assert plan.reuse_count == 2
        assert plan.transfer_count == 0
        assert plan.has_changes is False
        assert plan.is_first_sync is False

    def test_only_the_changed_chunk_needs_transfer(self) -> None:
        """A single edited chunk is the only one flagged for transfer."""
        path = Path("/f.bin")
        baseline = _collection(
            path, [_metadata(0, chunk_hash=_hash("a")), _metadata(1, chunk_hash=_hash("b"))]
        )
        current = _collection(
            path, [_metadata(0, chunk_hash=_hash("a")), _metadata(1, chunk_hash=_hash("c"))]
        )

        plan = DeltaCalculator().compute(baseline=baseline, current=current)

        assert plan.transfer_count == 1
        assert plan.reuse_count == 1
        assert plan.chunks_to_transfer[0].index == 1
        assert plan.bytes_to_transfer == plan.chunks_to_transfer[0].size

    def test_matches_by_hash_regardless_of_position(self) -> None:
        """A chunk that moved index but kept its bytes is still reused, not retransferred."""
        path = Path("/f.bin")
        baseline = _collection(
            path, [_metadata(0, chunk_hash=_hash("a")), _metadata(1, chunk_hash=_hash("b"))]
        )
        # Same two chunks' content, but reordered: "b" now comes first.
        current = _collection(
            path, [_metadata(0, chunk_hash=_hash("b")), _metadata(1, chunk_hash=_hash("a"))]
        )

        plan = DeltaCalculator().compute(baseline=baseline, current=current)

        assert plan.transfer_count == 0
        assert plan.reuse_count == 2

    def test_appended_content_only_transfers_the_new_chunk(self) -> None:
        """Appending a chunk to a file reuses every existing chunk unchanged."""
        path = Path("/f.bin")
        baseline = _collection(path, [_metadata(0, chunk_hash=_hash("a"))])
        current = _collection(
            path, [_metadata(0, chunk_hash=_hash("a")), _metadata(1, chunk_hash=_hash("b"))]
        )

        plan = DeltaCalculator().compute(baseline=baseline, current=current)

        assert plan.transfer_count == 1
        assert plan.chunks_to_transfer[0].index == 1

    def test_incompatible_source_path_raises(self) -> None:
        """Diffing against a baseline for a different file raises."""
        baseline = _collection(Path("/a.bin"), [_metadata(0, chunk_hash=_hash("a"))])
        current = _collection(Path("/b.bin"), [_metadata(0, chunk_hash=_hash("a"))])

        with pytest.raises(IncompatibleBaselineError):
            DeltaCalculator().compute(baseline=baseline, current=current)

    def test_unhashed_current_chunk_raises(self) -> None:
        """A current chunk with no recorded hash cannot be classified."""
        path = Path("/f.bin")
        baseline = _collection(path, [])
        current = _collection(path, [_metadata(0, chunk_hash=None)])

        with pytest.raises(UnhashedChunkError):
            DeltaCalculator().compute(baseline=baseline, current=current)


class TestDeltaPlanProperties:
    """Tests for `DeltaPlan`'s derived properties."""

    def test_reuse_count_is_total_minus_transfer(self) -> None:
        """`reuse_count` is always `current.chunk_count - transfer_count`."""
        path = Path("/f.bin")
        baseline = _collection(path, [_metadata(0, chunk_hash=_hash("a"))])
        current = _collection(
            path,
            [
                _metadata(0, chunk_hash=_hash("a")),
                _metadata(1, chunk_hash=_hash("b")),
                _metadata(2, chunk_hash=_hash("c")),
            ],
        )

        plan = DeltaCalculator().compute(baseline=baseline, current=current)

        assert plan.reuse_count == plan.current.chunk_count - plan.transfer_count
        assert plan.reuse_count == 1
        assert plan.transfer_count == 2
