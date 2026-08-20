"""Local filesystem implementation of the FileReconstructor port."""

from __future__ import annotations

from pathlib import Path

import structlog

from securesync.domain.chunk import Chunk
from securesync.domain.reconstruction import FileReconstructor
from securesync.shared.exceptions import ChunkEngineError

logger = structlog.get_logger(__name__)


class LocalFileReconstructor(FileReconstructor):
    """Writes a chunk's bytes at its offset within a file on the local filesystem.

    Uses ``r+b`` (in-place update) when the file already exists so
    other chunks already written stay intact, and pre-allocates up to
    the chunk's end offset for a brand-new file so `seek` past the
    current end doesn't leave a hole `write` can't fill.
    """

    def write_chunk_at_offset(self, destination: Path, chunk: Chunk) -> None:
        """See :meth:`FileReconstructor.write_chunk_at_offset`.

        Raises:
            ChunkEngineError: If creating the destination directory or
                writing to it fails.
        """
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            mode = "r+b" if destination.exists() else "w+b"
            with destination.open(mode) as file:
                file.seek(chunk.metadata.offset)
                file.write(chunk.data)
        except OSError as exc:
            raise ChunkEngineError(
                f"Failed to write chunk {chunk.metadata.chunk_id} into "
                f"{destination} at offset {chunk.metadata.offset}: {exc}"
            ) from exc
        logger.debug(
            "chunk_written_at_offset",
            chunk_id=chunk.metadata.chunk_id,
            destination=str(destination),
            offset=chunk.metadata.offset,
            size=chunk.metadata.size,
        )
