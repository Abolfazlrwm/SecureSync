"""Domain port for reconstructing a file from downloaded chunks.

Deliberately separate from :class:`~securesync.domain.chunking.ChunkWriter`:
that port writes a chunk's bytes as its own standalone file (e.g. into
a chunk store), which is the wrong shape for what
:class:`~securesync.application.use_cases.sync_file.SyncFileUseCase`
needs — writing a downloaded chunk's bytes at its correct byte offset
*within* one reconstructed target file. See
``docs/adr/0022-file-synchronization-use-case.md``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from securesync.domain.chunk import Chunk


class FileReconstructor(ABC):
    """Writes downloaded chunks into their correct position in a target file."""

    @abstractmethod
    def write_chunk_at_offset(self, destination: Path, chunk: Chunk) -> None:
        """Write `chunk`'s bytes into `destination` at `chunk.metadata.offset`.

        Creates `destination` (and its parent directories) if it
        doesn't exist yet. Does not truncate or otherwise disturb any
        of `destination`'s existing bytes outside the range this
        chunk occupies.

        Args:
            destination: The file being reconstructed.
            chunk: The chunk to write, including its target offset.

        Raises:
            OSError: If `destination` can't be created or written to.
        """
        raise NotImplementedError
