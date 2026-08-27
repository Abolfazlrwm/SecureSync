"""Shared pytest fixtures for the SecureSync test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.infrastructure.chunking.sha256_hash_provider import SHA256HashProvider
from securesync.infrastructure.chunking.streaming_chunk_reader import (
    FixedSizeChunkingStrategy,
    StreamingChunkReader,
)


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """A fresh temporary directory for a test."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    return tmp_path


@pytest.fixture
def storage_dir(tmp_path: Path) -> Path:
    """A fresh 'storage' subdirectory for a test."""
    d = tmp_path / "storage"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def sync_root(tmp_path: Path) -> Path:
    """A 'sync' directory that simulates what a peer would sync."""
    d = tmp_path / "sync"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def chunk_reader() -> StreamingChunkReader:
    """A real streaming chunk reader for filesystem-based tests."""
    return StreamingChunkReader()


@pytest.fixture
def chunk_strategy() -> FixedSizeChunkingStrategy:
    """Default fixed-size chunking strategy (4 MiB)."""
    return FixedSizeChunkingStrategy(chunk_size=64 * 1024)  # 64 KiB for fast tests


@pytest.fixture
def sha256_hasher() -> SHA256HashProvider:
    """Real SHA-256 hasher."""
    return SHA256HashProvider()


def make_chunk(
    index: int = 0,
    size: int = 1024,
    offset: int = 0,
    digest: str | None = None,
) -> Chunk:
    """Helper to construct a Chunk with correct metadata and dummy data.

    If ``digest`` is provided, the chunk is pre-hashed; otherwise
    ``chunk_hash`` is ``None`` (the state a ChunkReader yields before
    hashing runs).
    """
    data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    hash_obj = (
        ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=digest)
        if digest
        else None
    )
    metadata = ChunkMetadata(
        chunk_id=f"chunk-{index}",
        index=index,
        size=size,
        offset=offset,
        chunk_hash=hash_obj,
    )
    return Chunk(metadata=metadata, data=data)
