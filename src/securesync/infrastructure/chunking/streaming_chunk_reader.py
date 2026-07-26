"""``FixedSizeChunkingStrategy`` and the streaming ``ChunkReader`` adapter.

Neither class imports a hashing library — hashing is a separate
concern (:class:`~securesync.domain.chunking.ChunkHasher`).
"""

from __future__ import annotations

import io
import uuid
from collections.abc import Iterator
from pathlib import Path

from securesync.domain.chunk import Chunk, ChunkMetadata
from securesync.domain.chunk_exceptions import (
    ChunkingError,
    ChunkSourceAccessError,
    ChunkSourceNotFoundError,
    InvalidChunkSizeError,
)
from securesync.domain.chunking import ChunkingStrategy, ChunkReader

#: Default chunk size (4 MiB) used when a caller doesn't request one.
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024

#: Hard cap on how much is read from disk in a single I/O call,
#: regardless of the configured chunk size — bounds peak read-buffer
#: memory even for an unusually large custom chunk size.
_MAX_READ_BLOCK_BYTES = 16 * 1024 * 1024

#: Fixed namespace used to derive deterministic chunk IDs (see
#: ``_derive_chunk_id``). Arbitrary but stable — never change this
#: value, or previously derived chunk IDs will no longer reproduce.
_CHUNK_ID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "chunking.securesync")


class FixedSizeChunkingStrategy(ChunkingStrategy):
    """Splits a stream into equal-sized chunks; the final one may be shorter.

    The only :class:`~securesync.domain.chunking.ChunkingStrategy`
    implementation shipped in Phase 2. A future content-defined
    strategy implements the same port without requiring any change
    here, in :class:`StreamingChunkReader`, or in any application/
    domain code — see ADR-0007.
    """

    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
        """Initialize the strategy.

        Args:
            chunk_size: The size, in bytes, of every chunk except
                possibly the last. Defaults to 4 MiB.

        Raises:
            InvalidChunkSizeError: If ``chunk_size`` is not positive.
        """
        if chunk_size <= 0:
            raise InvalidChunkSizeError(f"chunk_size must be > 0, got {chunk_size}")
        self._chunk_size = chunk_size

    @property
    def chunk_size(self) -> int:
        """The configured chunk size, in bytes."""
        return self._chunk_size

    @property
    def name(self) -> str:
        """See :attr:`ChunkingStrategy.name`."""
        return "fixed-size"

    @property
    def preferred_read_block_size(self) -> int:
        """See :attr:`ChunkingStrategy.preferred_read_block_size`.

        Aligned with the configured chunk size so a chunk is typically
        assembled from a single read; :class:`StreamingChunkReader`
        still clamps this to its own hard cap.
        """
        return self._chunk_size

    def next_cut(self, buffered: memoryview, *, at_eof: bool) -> int | None:
        """See :meth:`ChunkingStrategy.next_cut`."""
        if len(buffered) >= self._chunk_size:
            return self._chunk_size
        if at_eof:
            return len(buffered) if buffered else None
        return None


class StreamingChunkReader(ChunkReader):
    """Streams a file's bytes and splits it into chunks via an injected strategy.

    Reads in bounded blocks (never more than ``_MAX_READ_BLOCK_BYTES``
    at a time) regardless of the configured chunk size, so peak memory
    use stays bounded even for an unusually large custom chunk size —
    and never scales with the file's total size, which is what lets
    this adapter process files far larger than available RAM (targeting
    100GB+).
    """

    def read_chunks(self, path: Path, strategy: ChunkingStrategy) -> Iterator[Chunk]:
        """See :meth:`ChunkReader.read_chunks`."""
        if not path.exists():
            raise ChunkSourceNotFoundError(f"Chunk source does not exist: {path}")
        if not path.is_file():
            raise ChunkSourceAccessError(f"Chunk source is not a regular file: {path}")
        try:
            yield from self._stream_chunks(path, strategy)
        except OSError as exc:
            raise ChunkSourceAccessError(f"Failed to read chunk source {path}: {exc}") from exc

    def _stream_chunks(self, path: Path, strategy: ChunkingStrategy) -> Iterator[Chunk]:
        read_block_size = max(1, min(strategy.preferred_read_block_size, _MAX_READ_BLOCK_BYTES))
        accumulator = bytearray()
        read_buffer = bytearray(read_block_size)
        index = 0
        offset = 0

        with path.open("rb") as file:
            while True:
                bytes_read = _read_full(file, read_buffer)
                if bytes_read:
                    accumulator += memoryview(read_buffer)[:bytes_read]
                at_eof = bytes_read == 0

                cut = strategy.next_cut(memoryview(accumulator), at_eof=at_eof)
                if cut is None:
                    if at_eof:
                        return
                    continue
                if cut <= 0:
                    raise ChunkingError(
                        f"{strategy.name} strategy returned a non-positive cut point: {cut}"
                    )

                data = bytes(accumulator[:cut])
                del accumulator[:cut]

                metadata = ChunkMetadata(
                    chunk_id=_derive_chunk_id(path, index),
                    index=index,
                    size=len(data),
                    offset=offset,
                )
                yield Chunk(metadata=metadata, data=data)

                offset += len(data)
                index += 1

                if at_eof and not accumulator:
                    return


def _read_full(file: io.BufferedReader, buffer: bytearray) -> int:
    """Fill ``buffer`` completely from ``file``, looping through short reads.

    A single ``readinto()`` call is permitted by the ``io`` API to
    return fewer bytes than requested even mid-file, not only at EOF
    (e.g. after an interrupted system call). Looping here until the
    buffer is full or the file is genuinely exhausted means a transient
    short read never truncates a chunk early.

    Args:
        file: An open binary file object.
        buffer: A pre-allocated buffer to fill.

    Returns:
        The number of bytes actually read into ``buffer`` — equal to
        ``len(buffer)`` unless the file ended first.
    """
    view = memoryview(buffer)
    total = 0
    while total < len(buffer):
        n = file.readinto(view[total:])
        if not n:
            break
        total += n
    return total


def _derive_chunk_id(path: Path, index: int) -> str:
    """Deterministically derive a stable chunk ID from source path and index.

    A namespaced UUID5 (not a random UUID4) means re-chunking the same
    file with the same index always yields the same chunk ID — useful
    for idempotent re-runs, caching, and reproducible tests.

    Args:
        path: The source file being chunked.
        index: The zero-based position of the chunk within the file.

    Returns:
        A stable, deterministic UUID string.
    """
    return str(uuid.uuid5(_CHUNK_ID_NAMESPACE, f"{path}:{index}"))
