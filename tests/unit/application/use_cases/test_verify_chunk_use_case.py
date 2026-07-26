"""Unit tests for `securesync.application.use_cases.verify_chunk.VerifyChunkUseCase`."""

from __future__ import annotations

import pytest

from securesync.application.use_cases.verify_chunk import VerifyChunkUseCase
from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.domain.chunk_exceptions import ChunkVerificationError
from tests.doubles import FakeChunkHasher


def _hashed_chunk(data: bytes, chunk_hash: ChunkHash | None) -> Chunk:
    metadata = ChunkMetadata(
        chunk_id="chunk-0", index=0, size=len(data), offset=0, chunk_hash=chunk_hash
    )
    return Chunk(metadata=metadata, data=data)


class TestExecute:
    """Tests for `VerifyChunkUseCase.execute`."""

    async def test_matching_hash_returns_true(self) -> None:
        """A chunk whose data still hashes to its recorded hash verifies as `True`."""
        hasher = FakeChunkHasher()
        recorded_hash = hasher.hash(b"payload")
        chunk = _hashed_chunk(b"payload", recorded_hash)
        use_case = VerifyChunkUseCase(hasher=FakeChunkHasher())

        assert await use_case.execute(chunk) is True

    async def test_tampered_data_returns_false(self) -> None:
        """A chunk whose data no longer matches its recorded hash verifies as `False`."""
        hasher = FakeChunkHasher()
        recorded_hash = hasher.hash(b"original")
        tampered_chunk = _hashed_chunk(b"tampered!", recorded_hash)
        use_case = VerifyChunkUseCase(hasher=FakeChunkHasher())

        assert await use_case.execute(tampered_chunk) is False

    async def test_missing_recorded_hash_raises(self) -> None:
        """A chunk with no recorded hash can't be verified against anything."""
        chunk = _hashed_chunk(b"data", None)
        use_case = VerifyChunkUseCase(hasher=FakeChunkHasher())

        with pytest.raises(ChunkVerificationError, match="no recorded hash"):
            await use_case.execute(chunk)

    async def test_uses_the_injected_hasher(self) -> None:
        """Verification re-hashes via the injected hasher, not some other mechanism."""
        wrong_hash = ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest="a" * 64)
        chunk = _hashed_chunk(b"data", wrong_hash)
        hasher = FakeChunkHasher()
        use_case = VerifyChunkUseCase(hasher=hasher)

        await use_case.execute(chunk)

        assert hasher.calls == [b"data"]
