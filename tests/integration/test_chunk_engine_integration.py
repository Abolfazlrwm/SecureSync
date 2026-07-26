"""Integration tests: chunk-engine use cases + real infrastructure adapters.

These tests wire `ChunkFileUseCase`, `VerifyChunkUseCase`, and
`CalculateChunkHashesUseCase` (application layer) to real
`StreamingChunkReader`, `SHA256HashProvider`, `ChunkFileWriter`, and
`FileChunkRepository` adapters (infrastructure layer) against real
temporary files, verifying every layer cooperates correctly end-to-end
- composition-root-style dependency injection, exactly as a future
presentation layer would do it.
"""

from __future__ import annotations

import os
from pathlib import Path

from securesync.application.use_cases.calculate_chunk_hashes import CalculateChunkHashesUseCase
from securesync.application.use_cases.chunk_file import ChunkFileUseCase
from securesync.application.use_cases.verify_chunk import VerifyChunkUseCase
from securesync.infrastructure.chunking.chunk_file_writer import ChunkFileWriter
from securesync.infrastructure.chunking.file_chunk_repository import FileChunkRepository
from securesync.infrastructure.chunking.sha256_hash_provider import SHA256HashProvider
from securesync.infrastructure.chunking.streaming_chunk_reader import (
    FixedSizeChunkingStrategy,
    StreamingChunkReader,
)


class TestChunkFileUseCaseIntegration:
    """End-to-end tests through `ChunkFileUseCase`, injected with real adapters."""

    async def test_chunks_a_real_file_and_every_chunk_verifies(self, tmp_path: Path) -> None:
        """Every chunk produced from a real file re-verifies against its own hash."""
        original = os.urandom(300_000)
        source = tmp_path / "source.bin"
        source.write_bytes(original)

        chunk_use_case = ChunkFileUseCase(
            reader=StreamingChunkReader(), hasher=SHA256HashProvider()
        )
        verify_use_case = VerifyChunkUseCase(hasher=SHA256HashProvider())
        strategy = FixedSizeChunkingStrategy(chunk_size=4096)

        reconstructed = bytearray()
        async for chunk in chunk_use_case.execute(source, strategy):
            assert await verify_use_case.execute(chunk) is True
            reconstructed.extend(chunk.data)

        assert bytes(reconstructed) == original

    async def test_chunks_written_to_disk_reread_and_verify(self, tmp_path: Path) -> None:
        """Chunks written via `ChunkFileWriter` can be reread and still verify."""
        original = os.urandom(50_000)
        source = tmp_path / "source.bin"
        source.write_bytes(original)
        chunks_dir = tmp_path / "chunks"

        chunk_use_case = ChunkFileUseCase(
            reader=StreamingChunkReader(), hasher=SHA256HashProvider()
        )
        writer = ChunkFileWriter()
        strategy = FixedSizeChunkingStrategy(chunk_size=8192)

        expected: dict[Path, bytes] = {}
        async for chunk in chunk_use_case.execute(source, strategy):
            destination = chunks_dir / chunk.metadata.chunk_id
            writer.write_chunk(destination, chunk)
            expected[destination] = chunk.data

        assert expected  # sanity: the file actually produced chunks
        for destination, original_data in expected.items():
            assert destination.read_bytes() == original_data


class TestCalculateChunkHashesUseCaseIntegration:
    """End-to-end tests through `CalculateChunkHashesUseCase` and `FileChunkRepository`."""

    async def test_manifest_round_trips_through_the_repository(self, tmp_path: Path) -> None:
        """A manifest built from a real file survives a save/load round trip."""
        original = os.urandom(20_000)
        source = tmp_path / "source.bin"
        source.write_bytes(original)

        use_case = CalculateChunkHashesUseCase(
            reader=StreamingChunkReader(), hasher=SHA256HashProvider()
        )
        repository = FileChunkRepository(storage_dir=tmp_path / "manifests")
        strategy = FixedSizeChunkingStrategy(chunk_size=1024)

        manifest = await use_case.build_manifest(source, strategy, chunk_size=1024)
        repository.save(manifest)
        loaded = repository.load(source)

        assert loaded == manifest
        assert loaded is not None
        assert loaded.total_size == len(original)
        assert all(chunk.chunk_hash is not None for chunk in loaded.chunks)

    async def test_manifest_hashes_match_a_full_chunk_file_pass(self, tmp_path: Path) -> None:
        """The metadata-only pass produces the same hashes as the bytes-retaining pass."""
        original = os.urandom(20_000)
        source = tmp_path / "source.bin"
        source.write_bytes(original)
        strategy_a = FixedSizeChunkingStrategy(chunk_size=1024)
        strategy_b = FixedSizeChunkingStrategy(chunk_size=1024)

        hash_use_case = CalculateChunkHashesUseCase(
            reader=StreamingChunkReader(), hasher=SHA256HashProvider()
        )
        chunk_use_case = ChunkFileUseCase(
            reader=StreamingChunkReader(), hasher=SHA256HashProvider()
        )

        metadata_only = [m async for m in hash_use_case.execute(source, strategy_a)]
        full_chunks = [c async for c in chunk_use_case.execute(source, strategy_b)]

        assert [m.chunk_hash for m in metadata_only] == [c.metadata.chunk_hash for c in full_chunks]
