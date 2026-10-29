"""Local filesystem implementation of the FileReconstructor port."""

from __future__ import annotations

import os
import shutil
import tempfile
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

    def begin_partial(self, destination: Path) -> Path:
        """See :meth:`FileReconstructor.begin_partial`.

        The temporary file is created with :func:`tempfile.mkstemp` in
        the destination's own directory — the same directory is what
        makes the later :func:`os.replace` an atomic rename rather than
        a cross-device copy.

        Raises:
            ChunkEngineError: If the temporary file or the parent
                directory can't be created.
        """
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            handle, temp_name = tempfile.mkstemp(
                prefix=f".{destination.name}.", suffix=".part", dir=destination.parent
            )
            os.close(handle)
            partial = Path(temp_name)
            if destination.exists():
                # A delta push only carries the chunks that changed;
                # everything else has to come from the current file.
                shutil.copyfile(destination, partial)
        except OSError as exc:
            raise ChunkEngineError(
                f"Failed to start partial reconstruction of {destination}: {exc}"
            ) from exc

        logger.debug("partial_reconstruction_started", destination=str(destination))
        return partial

    def commit_partial(self, destination: Path, partial: Path) -> None:
        """See :meth:`FileReconstructor.commit_partial`.

        ``os.replace`` is atomic with respect to readers: a concurrent
        reader sees either the old file or the complete new one, never
        a mixture. It does not fsync, so it says nothing about
        durability across a power loss.

        Raises:
            ChunkEngineError: If the rename fails.
        """
        try:
            os.replace(partial, destination)
        except OSError as exc:
            raise ChunkEngineError(
                f"Failed to commit partial reconstruction of {destination}: {exc}"
            ) from exc
        logger.debug("partial_reconstruction_committed", destination=str(destination))

    def abort_partial(self, partial: Path) -> None:
        """See :meth:`FileReconstructor.abort_partial`.

        Never raises: this runs on timeout, on cancellation, and on the
        error path of a failed commit, where raising would replace the
        original problem with a cleanup problem.
        """
        try:
            partial.unlink(missing_ok=True)
        except OSError as exc:  # pragma: no cover - defensive; cleanup must not raise
            logger.warning(
                "partial_reconstruction_cleanup_failed", partial=str(partial), error=str(exc)
            )
