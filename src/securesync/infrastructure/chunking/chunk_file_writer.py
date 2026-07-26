"""Filesystem-based implementation of the ``ChunkWriter`` port."""

from __future__ import annotations

from pathlib import Path

import structlog

from securesync.domain.chunk import Chunk
from securesync.domain.chunking import ChunkWriter
from securesync.infrastructure.chunking._atomic_write import atomic_write_bytes
from securesync.shared.exceptions import ChunkEngineError

logger = structlog.get_logger(__name__)


class ChunkFileWriter(ChunkWriter):
    """Writes a chunk's bytes to a file on the local filesystem.

    Writes atomically (see :func:`atomic_write_bytes`), creating parent
    directories as needed, so a crash or a concurrent reader never
    observes a partially written chunk file at the destination.
    """

    def write_chunk(self, destination: Path, chunk: Chunk) -> None:
        """See :meth:`ChunkWriter.write_chunk`.

        Raises:
            ChunkEngineError: If creating the destination directory,
                writing, or renaming the temporary file fails.
        """
        try:
            atomic_write_bytes(destination, chunk.data, temp_suffix=chunk.metadata.chunk_id)
        except OSError as exc:
            raise ChunkEngineError(
                f"Failed to write chunk {chunk.metadata.chunk_id} to {destination}: {exc}"
            ) from exc
        logger.debug(
            "chunk_written",
            chunk_id=chunk.metadata.chunk_id,
            destination=str(destination),
            size=chunk.metadata.size,
        )
