"""Use case: split a file into fully hashed chunks, streaming throughout."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import structlog

from securesync.domain.chunk import Chunk
from securesync.domain.chunking import ChunkHasher, ChunkingStrategy, ChunkReader
from securesync.utils.async_iter import iter_in_thread

logger = structlog.get_logger(__name__)


class ChunkFileUseCase:
    """Splits a file into chunks and hashes each one, without full-file buffering.

    Composes an injected :class:`ChunkReader` (splitting) and
    :class:`ChunkHasher` (digesting); contains no chunking or hashing
    logic of its own, consistent with Dependency Inversion — both
    concerns are supplied by the composition root. The reading and
    hashing themselves run synchronously in a worker thread (see
    :func:`~securesync.utils.async_iter.iter_in_thread`), so the event
    loop is never blocked, while chunks still cross back to the caller
    one at a time — the whole file is never buffered, even across the
    async boundary.
    """

    def __init__(self, reader: ChunkReader, hasher: ChunkHasher) -> None:
        """Initialize the use case.

        Args:
            reader: Concrete chunk-reading adapter, injected by the
                composition root.
            hasher: Concrete hashing adapter, injected by the
                composition root.
        """
        self._reader = reader
        self._hasher = hasher

    async def execute(self, path: Path, strategy: ChunkingStrategy) -> AsyncIterator[Chunk]:
        """Lazily yield every hashed chunk of ``path``, in order.

        Args:
            path: The file to chunk.
            strategy: Decides where each chunk boundary falls.

        Yields:
            Fully hashed :class:`~securesync.domain.chunk.Chunk`
            objects, in ascending index order.

        Raises:
            ChunkSourceNotFoundError: If ``path`` doesn't exist.
            ChunkSourceAccessError: If ``path`` can't be read.
        """
        logger.info("chunking_started", path=str(path), strategy=strategy.name)
        chunk_count = 0
        total_bytes = 0
        async for chunk in iter_in_thread(self._read_and_hash(path, strategy)):
            chunk_count += 1
            total_bytes += chunk.metadata.size
            yield chunk
        logger.info(
            "chunking_completed",
            path=str(path),
            chunk_count=chunk_count,
            total_bytes=total_bytes,
        )

    def _read_and_hash(self, path: Path, strategy: ChunkingStrategy) -> Iterator[Chunk]:
        """Read and hash chunks synchronously; runs inside a worker thread."""
        for chunk in self._reader.read_chunks(path, strategy):
            yield chunk.with_hash(self._hasher.hash(chunk.data))
