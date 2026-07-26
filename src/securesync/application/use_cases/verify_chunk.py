"""Use case: verify a chunk's content against its recorded hash."""

from __future__ import annotations

import asyncio

import structlog

from securesync.domain.chunk import Chunk
from securesync.domain.chunk_exceptions import ChunkVerificationError
from securesync.domain.chunking import ChunkHasher

logger = structlog.get_logger(__name__)


class VerifyChunkUseCase:
    """Verifies that a chunk's actual bytes match its recorded hash.

    Re-hashing runs in a worker thread (:func:`asyncio.to_thread`) so
    the event loop is never blocked by the hashing work.
    """

    def __init__(self, hasher: ChunkHasher) -> None:
        """Initialize the use case.

        Args:
            hasher: Concrete hashing adapter, injected by the
                composition root. Must use the same algorithm the
                chunk was originally hashed with.
        """
        self._hasher = hasher

    async def execute(self, chunk: Chunk) -> bool:
        """Return whether ``chunk.data`` hashes to ``chunk.metadata.chunk_hash``.

        Args:
            chunk: The chunk to verify. Must already carry a recorded
                hash (typically produced by
                :class:`~securesync.application.use_cases.chunk_file.ChunkFileUseCase`
                or
                :class:`~securesync.application.use_cases.calculate_chunk_hashes.CalculateChunkHashesUseCase`).

        Returns:
            ``True`` if re-hashing ``chunk.data`` reproduces
            ``chunk.metadata.chunk_hash`` exactly, ``False`` otherwise.
            A mismatch is a normal, expected outcome (e.g. corrupted or
            tampered data) — it is returned, not raised.

        Raises:
            ChunkVerificationError: If ``chunk.metadata.chunk_hash`` is
                ``None`` — there is nothing recorded to verify against.
        """
        recorded_hash = chunk.metadata.chunk_hash
        if recorded_hash is None:
            raise ChunkVerificationError(
                f"chunk {chunk.metadata.chunk_id} has no recorded hash to verify against"
            )
        actual_hash = await asyncio.to_thread(self._hasher.hash, chunk.data)
        matches = actual_hash == recorded_hash
        logger.debug("chunk_verified", chunk_id=chunk.metadata.chunk_id, matches=matches)
        return matches
