"""Domain port for reconstructing a file from downloaded chunks.

Deliberately separate from :class:`~securesync.domain.chunking.ChunkWriter`:
that port writes a chunk's bytes as its own standalone file (e.g. into
a chunk store), which is the wrong shape for what
:class:`~securesync.application.use_cases.sync_file.SyncFileUseCase`
needs — writing a downloaded chunk's bytes at its correct byte offset
*within* one reconstructed target file. See
``docs/adr/0022-file-synchronization-use-case.md``.

The ``*_partial`` methods model a file that is being assembled over
several messages from an untrusted peer. They exist so that a
half-finished file is never visible at its real path: bytes accumulate
in a sibling temporary file, and only a completed reconstruction is
moved into place, atomically, with a single rename. Without that, an
interrupted or hostile transfer leaves a truncated file at a name the
user believes is complete — and a reader (or the next sync) sees torn
content that was never a valid version of anything.
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

    @abstractmethod
    def begin_partial(self, destination: Path) -> Path:
        """Start assembling `destination` in a temporary sibling file.

        The temporary file is seeded with `destination`'s current bytes
        when it exists, so a partial (delta) transfer that only supplies
        the changed chunks still ends up with a complete file.

        Args:
            destination: The file that will eventually be replaced.

        Returns:
            The path of the temporary file, to pass to
            :meth:`write_chunk_at_offset` and later to
            :meth:`commit_partial` or :meth:`abort_partial`.

        Raises:
            OSError: If the parent directory or temporary file can't be created.
        """
        raise NotImplementedError

    @abstractmethod
    def commit_partial(self, destination: Path, partial: Path) -> None:
        """Atomically move `partial` into place as `destination`.

        Args:
            destination: The final path.
            partial: The temporary file produced by :meth:`begin_partial`.

        Raises:
            OSError: If the rename fails.
        """
        raise NotImplementedError

    @abstractmethod
    def abort_partial(self, partial: Path) -> None:
        """Discard `partial`, leaving `destination` exactly as it was.

        Must be safe to call when the file has already been removed —
        cleanup runs on timeout, on cancellation, and after a failed
        commit, and none of those may raise.

        Args:
            partial: The temporary file produced by :meth:`begin_partial`.
        """
        raise NotImplementedError
