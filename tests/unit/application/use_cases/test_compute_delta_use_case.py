"""Unit tests for `ComputeDeltaUseCase`."""

from __future__ import annotations

from pathlib import Path

from securesync.application.use_cases.calculate_chunk_hashes import CalculateChunkHashesUseCase
from securesync.application.use_cases.compute_delta import ComputeDeltaUseCase
from securesync.domain.chunk import Chunk, ChunkMetadata
from securesync.infrastructure.chunking.streaming_chunk_reader import FixedSizeChunkingStrategy
from tests.doubles import FakeChunkHasher, FakeChunkReader, FakeChunkRepository


def _chunk(index: int, data: bytes) -> Chunk:
    metadata = ChunkMetadata(
        chunk_id=f"chunk-{index}", index=index, size=len(data), offset=index * len(data)
    )
    return Chunk(metadata=metadata, data=data)


def _use_case(chunks: list[Chunk], repository: FakeChunkRepository) -> ComputeDeltaUseCase:
    hash_use_case = CalculateChunkHashesUseCase(
        reader=FakeChunkReader(chunks), hasher=FakeChunkHasher()
    )
    return ComputeDeltaUseCase(chunk_hasher_use_case=hash_use_case, repository=repository)


class TestExecute:
    """Tests for `ComputeDeltaUseCase.execute`."""

    async def test_first_sync_has_no_baseline_and_transfers_everything(self) -> None:
        """With nothing in the repository yet, every chunk must be transferred."""
        path = Path("/f.bin")
        use_case = _use_case([_chunk(0, b"1234"), _chunk(1, b"5678")], FakeChunkRepository())

        plan = await use_case.execute(path, FixedSizeChunkingStrategy(chunk_size=4), chunk_size=4)

        assert plan.is_first_sync is True
        assert plan.transfer_count == 2
        assert plan.source_path == path

    async def test_unchanged_file_reuses_every_chunk(self) -> None:
        """Diffing against a baseline built from identical bytes reuses everything."""
        path = Path("/f.bin")
        repository = FakeChunkRepository()
        chunks = [_chunk(0, b"1234"), _chunk(1, b"5678")]
        strategy = FixedSizeChunkingStrategy(chunk_size=4)

        # Prime the repository with a baseline computed from the same bytes.
        priming_use_case = _use_case(chunks, repository)
        baseline_plan = await priming_use_case.execute(path, strategy, chunk_size=4)
        repository.save(baseline_plan.current)

        use_case = _use_case([_chunk(0, b"1234"), _chunk(1, b"5678")], repository)
        plan = await use_case.execute(path, strategy, chunk_size=4)

        assert plan.is_first_sync is False
        assert plan.reuse_count == 2
        assert plan.transfer_count == 0

    async def test_does_not_mutate_the_repository(self) -> None:
        """Computing a plan never saves the new manifest as a side effect."""
        path = Path("/f.bin")
        repository = FakeChunkRepository()
        use_case = _use_case([_chunk(0, b"1234")], repository)

        await use_case.execute(path, FixedSizeChunkingStrategy(chunk_size=4), chunk_size=4)

        assert repository.save_calls == 0

    async def test_loads_the_baseline_for_the_requested_path(self) -> None:
        """The repository is queried for exactly the path being diffed."""
        path = Path("/f.bin")
        repository = FakeChunkRepository()
        use_case = _use_case([_chunk(0, b"1234")], repository)

        await use_case.execute(path, FixedSizeChunkingStrategy(chunk_size=4), chunk_size=4)

        assert repository.load_calls == 1

    async def test_returned_plan_carries_the_current_manifest(self) -> None:
        """`plan.current` is the manifest a caller would persist to update the cache."""
        path = Path("/f.bin")
        use_case = _use_case([_chunk(0, b"1234")], FakeChunkRepository())

        plan = await use_case.execute(path, FixedSizeChunkingStrategy(chunk_size=4), chunk_size=4)

        assert plan.current.source_path == path
        assert plan.current.chunk_count == 1
