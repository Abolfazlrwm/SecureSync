"""Use case: compute chunk hashes for a file without retaining chunk bytes."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import structlog

from securesync.domain.chunk import ChunkCollection, ChunkMetadata
from securesync.domain.chunking import ChunkHasher, ChunkingStrategy, ChunkReader
from securesync.utils.async_iter import iter_in_thread

logger = structlog.get_logger(__name__)


class CalculateChunkHashesUseCase:
    """Computes chunk hashes for a file without retaining any chunk's bytes.

    Unlike :class:`~securesync.application.use_cases.chunk_file.ChunkFileUseCase`,
    which yields fully materialized chunks for a caller that needs the
    bytes (e.g. to persist them), this use case is for callers that
    only need the resulting digests — a manifest, or a verification
    pass. Each chunk's bytes are dropped as soon as its hash is
    computed and are never exposed to the caller.
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

    async def execute(self, path: Path, strategy: ChunkingStrategy) -> AsyncIterator[ChunkMetadata]:
        """Lazily yield hashed metadata for every chunk of ``path``, in order.

        Args:
            path: The file to process.
            strategy: Decides where each chunk boundary falls.

        Yields:
            :class:`~securesync.domain.chunk.ChunkMetadata` with
            ``chunk_hash`` populated, in ascending index order.

        Raises:
            ChunkSourceNotFoundError: If ``path`` doesn't exist.
            ChunkSourceAccessError: If ``path`` can't be read.
        """
        async for metadata in iter_in_thread(self._hash_chunks(path, strategy)):
            yield metadata

    async def build_manifest(
        self, path: Path, strategy: ChunkingStrategy, *, chunk_size: int
    ) -> ChunkCollection:
        """Compute and summarize every chunk of ``path`` as one manifest.

        Consumes the same streaming pipeline as :meth:`execute` but
        accumulates only metadata — the returned collection costs
        memory proportional to chunk *count*, not file size.

        Args:
            path: The file to process.
            strategy: Decides where each chunk boundary falls.
            chunk_size: Recorded on the resulting collection as its
                nominal chunk size (see
                :attr:`~securesync.domain.chunk.ChunkCollection.chunk_size`).

        Returns:
            The completed manifest.

        Raises:
            ChunkSourceNotFoundError: If ``path`` doesn't exist.
            ChunkSourceAccessError: If ``path`` can't be read.
        """
        collected: list[ChunkMetadata] = []
        total_size = 0
        async for metadata in self.execute(path, strategy):
            collected.append(metadata)
            total_size += metadata.size
        logger.info(
            "chunk_manifest_built",
            path=str(path),
            chunk_count=len(collected),
            total_bytes=total_size,
        )
        return ChunkCollection(
            source_path=path,
            chunk_size=chunk_size,
            total_size=total_size,
            chunks=tuple(collected),
        )

    def _hash_chunks(self, path: Path, strategy: ChunkingStrategy) -> Iterator[ChunkMetadata]:
        """Read and hash chunks synchronously, dropping bytes immediately.

        Runs inside a worker thread, driven by :meth:`execute`.
        """
        for chunk in self._reader.read_chunks(path, strategy):
            yield chunk.metadata.with_hash(self._hasher.hash(chunk.data))
