"""Integration tests: `ComputeDeltaUseCase` + real chunk-engine infrastructure.

Wires `ComputeDeltaUseCase` and `CalculateChunkHashesUseCase` (application
layer) to real `StreamingChunkReader`, `SHA256HashProvider`, and
`FileChunkRepository` adapters (infrastructure layer) against real
temporary files, verifying the whole delta-computation pipeline
cooperates correctly end-to-end.
"""

from __future__ import annotations

import os
from pathlib import Path

from securesync.application.use_cases.calculate_chunk_hashes import CalculateChunkHashesUseCase
from securesync.application.use_cases.compute_delta import ComputeDeltaUseCase
from securesync.infrastructure.chunking.file_chunk_repository import FileChunkRepository
from securesync.infrastructure.chunking.sha256_hash_provider import SHA256HashProvider
from securesync.infrastructure.chunking.streaming_chunk_reader import (
    FixedSizeChunkingStrategy,
    StreamingChunkReader,
)


def _make_use_case(
    storage_dir: Path,
) -> tuple[ComputeDeltaUseCase, FileChunkRepository]:
    hash_use_case = CalculateChunkHashesUseCase(
        reader=StreamingChunkReader(), hasher=SHA256HashProvider()
    )
    repository = FileChunkRepository(storage_dir=storage_dir)
    use_case = ComputeDeltaUseCase(chunk_hasher_use_case=hash_use_case, repository=repository)
    return use_case, repository


class TestDeltaSyncIntegration:
    """End-to-end delta computation against real files on a real filesystem."""

    async def test_first_sync_of_a_real_file_transfers_every_chunk(self, tmp_path: Path) -> None:
        """A file with no recorded baseline needs every chunk transferred."""
        source = tmp_path / "source.bin"
        source.write_bytes(os.urandom(20_000))
        use_case, _ = _make_use_case(tmp_path / "manifests")
        strategy = FixedSizeChunkingStrategy(chunk_size=1024)

        plan = await use_case.execute(source, strategy, chunk_size=1024)

        assert plan.is_first_sync is True
        assert plan.transfer_count == plan.current.chunk_count
        assert plan.reuse_count == 0

    async def test_untouched_file_has_nothing_to_transfer_on_second_sync(
        self, tmp_path: Path
    ) -> None:
        """Re-diffing an unmodified file after saving its baseline finds no changes."""
        source = tmp_path / "source.bin"
        source.write_bytes(os.urandom(20_000))
        use_case, repository = _make_use_case(tmp_path / "manifests")
        strategy = FixedSizeChunkingStrategy(chunk_size=1024)

        first_plan = await use_case.execute(source, strategy, chunk_size=1024)
        repository.save(first_plan.current)

        second_plan = await use_case.execute(source, strategy, chunk_size=1024)

        assert second_plan.has_changes is False
        assert second_plan.reuse_count == second_plan.current.chunk_count

    async def test_appending_data_only_transfers_the_new_tail(self, tmp_path: Path) -> None:
        """Appending bytes to a synced file only flags the newly appended chunks."""
        source = tmp_path / "source.bin"
        original = os.urandom(4096)
        source.write_bytes(original)
        use_case, repository = _make_use_case(tmp_path / "manifests")
        strategy = FixedSizeChunkingStrategy(chunk_size=1024)

        baseline_plan = await use_case.execute(source, strategy, chunk_size=1024)
        repository.save(baseline_plan.current)
        assert baseline_plan.current.chunk_count == 4

        source.write_bytes(original + os.urandom(1024))
        plan = await use_case.execute(source, strategy, chunk_size=1024)

        assert plan.current.chunk_count == 5
        assert plan.transfer_count == 1
        assert plan.reuse_count == 4
        assert plan.chunks_to_transfer[0].index == 4

    async def test_editing_one_chunk_leaves_the_others_reusable(self, tmp_path: Path) -> None:
        """Overwriting bytes inside a single chunk only flags that one chunk."""
        source = tmp_path / "source.bin"
        chunk_a, chunk_b, chunk_c = os.urandom(1024), os.urandom(1024), os.urandom(1024)
        source.write_bytes(chunk_a + chunk_b + chunk_c)
        use_case, repository = _make_use_case(tmp_path / "manifests")
        strategy = FixedSizeChunkingStrategy(chunk_size=1024)

        baseline_plan = await use_case.execute(source, strategy, chunk_size=1024)
        repository.save(baseline_plan.current)

        edited_b = os.urandom(1024)
        source.write_bytes(chunk_a + edited_b + chunk_c)
        plan = await use_case.execute(source, strategy, chunk_size=1024)

        assert plan.transfer_count == 1
        assert plan.chunks_to_transfer[0].index == 1
        assert plan.bytes_to_transfer == 1024
