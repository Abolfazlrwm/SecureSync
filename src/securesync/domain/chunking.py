"""Ports (interfaces) for the chunk engine.

This module defines the boundary between the domain and any concrete
chunking, hashing, reading, writing, or persistence technology.
Application code depends only on these abstractions; infrastructure
adapters implement them. Nothing here performs I/O or imports a
hashing library — see ``docs/adr/0007-chunking-strategy-as-a-pluggable-port.md``
for the reasoning behind this split.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from securesync.domain.chunk import Chunk, ChunkCollection, ChunkHash

_DEFAULT_PREFERRED_READ_BLOCK_SIZE = 1 * 1024 * 1024  # 1 MiB


class ChunkingStrategy(ABC):
    """Strategy-pattern port for deciding where one chunk ends and the next begins.

    ``ChunkReader`` implementations (infrastructure) own all actual file
    I/O; a strategy never reads from disk itself. Instead the reader
    feeds it the bytes accumulated so far for the chunk currently being
    assembled, and the strategy answers how many of those leading bytes
    belong to that chunk. This pull-based split is what lets a future
    content-defined strategy — ``RollingHashChunkingStrategy``,
    ``RabinFingerprintChunkingStrategy``, ``FastCDCChunkingStrategy``,
    all of which must inspect actual byte content to choose a cut point
    — be added as a new adapter with zero change to ``ChunkReader`` or
    to any application/domain code that depends on this port. Only
    ``FixedSizeChunkingStrategy`` (infrastructure) is implemented in
    Phase 2; see ADR-0007.
    """

    @abstractmethod
    def next_cut(self, buffered: memoryview, *, at_eof: bool) -> int | None:
        """Decide how many of ``buffered``'s leading bytes end the current chunk.

        Args:
            buffered: Every byte read so far for the chunk currently
                being assembled, from its start. A read-only view; an
                implementation must not assume it can hold onto this
                view past the call, since the caller may reuse or
                mutate the underlying buffer afterwards.
            at_eof: Whether the underlying stream has no more bytes
                after ``buffered`` (the file ended, possibly mid-chunk).

        Returns:
            The number of leading bytes of ``buffered`` that end the
            current chunk (a cut point), which must be strictly
            positive, or ``None`` if no boundary has been found yet and
            the caller should read more data before asking again. When
            ``at_eof`` is ``True`` and ``buffered`` is non-empty, an
            implementation must return a cut point (even if that means
            "all of ``buffered``"), since no more data will ever
            arrive. When ``at_eof`` is ``True`` and ``buffered`` is
            empty, an implementation must return ``None`` — there is
            nothing left to cut.
        """
        raise NotImplementedError

    @property
    def preferred_read_block_size(self) -> int:
        """Hint: how many bytes a reader should read per I/O call.

        Not abstract — every strategy gets a sane default (1 MiB) for
        free, sized for a content-defined strategy's typical rolling
        window. ``FixedSizeChunkingStrategy`` overrides this to align
        with its configured chunk size. A reader is free to clamp this
        hint to its own hard cap; it exists purely to avoid needless
        small reads or oversized ones, never to change correctness.
        """
        return _DEFAULT_PREFERRED_READ_BLOCK_SIZE

    @property
    @abstractmethod
    def name(self) -> str:
        """A short, stable identifier for this strategy (e.g. ``"fixed-size"``)."""
        raise NotImplementedError


class ChunkReader(ABC):
    """Port for splitting a file into chunks without loading it fully into memory.

    Implementations stream a file's bytes and delegate every boundary
    decision to an injected :class:`ChunkingStrategy`, producing
    :class:`~securesync.domain.chunk.Chunk` objects with
    ``metadata.chunk_hash`` left as ``None`` — hashing is a separate
    concern, owned by :class:`ChunkHasher`. Peak memory use must stay
    bounded by the chunk size in use, never by the file's total size.
    """

    @abstractmethod
    def read_chunks(self, path: Path, strategy: ChunkingStrategy) -> Iterator[Chunk]:
        """Lazily yield every chunk of ``path``, in order, unhashed.

        Args:
            path: The file to read. Must exist and be a regular,
                readable file.
            strategy: Decides where each chunk boundary falls.

        Yields:
            One :class:`~securesync.domain.chunk.Chunk` per boundary
            ``strategy`` produces, in ascending offset order, with
            ``metadata.chunk_hash`` unset. Yields nothing for an empty
            file.

        Raises:
            ChunkSourceNotFoundError: If ``path`` doesn't exist.
            ChunkSourceAccessError: If ``path`` can't be opened or read
                (e.g. a permissions error, or it isn't a regular file).
        """
        raise NotImplementedError


class ChunkHasher(ABC):
    """Port for computing a chunk's content digest."""

    @abstractmethod
    def hash(self, data: bytes | memoryview) -> ChunkHash:
        """Compute the digest of ``data``.

        Args:
            data: The chunk's raw bytes.

        Returns:
            A :class:`~securesync.domain.chunk.ChunkHash`. Deterministic:
            hashing the same bytes twice always produces the same
            digest.
        """
        raise NotImplementedError


class ChunkWriter(ABC):
    """Port for persisting a chunk's bytes to durable storage."""

    @abstractmethod
    def write_chunk(self, destination: Path, chunk: Chunk) -> None:
        """Write ``chunk``'s bytes to ``destination``.

        Args:
            destination: Where to write the chunk's bytes.
            chunk: The chunk to persist.

        Raises:
            OSError: Implementations propagate or wrap the underlying
                I/O failure; see the concrete adapter's own docstring
                for the exact exception type it raises.
        """
        raise NotImplementedError


class ChunkRepository(ABC):
    """Port for storing and retrieving a file's chunk manifest.

    A temporary, filesystem-backed implementation
    (``FileChunkRepository``, infrastructure) is provided in Phase 2;
    the metadata database planned for Phase 8 (see ``ROADMAP.md``) is
    expected to become the primary implementation later, behind this
    same port — callers never need to change when that adapter is
    swapped in.
    """

    @abstractmethod
    def save(self, collection: ChunkCollection) -> None:
        """Persist ``collection`` so it can be retrieved later by source path.

        Args:
            collection: The manifest to persist. Overwrites any
                manifest previously saved for the same
                ``collection.source_path``.

        Raises:
            OSError: Implementations propagate or wrap the underlying
                I/O failure; see the concrete adapter's own docstring
                for the exact exception type it raises.
        """
        raise NotImplementedError

    @abstractmethod
    def load(self, source_path: Path) -> ChunkCollection | None:
        """Retrieve a previously saved manifest for ``source_path``.

        Args:
            source_path: The original file path the manifest describes.

        Returns:
            The saved
            :class:`~securesync.domain.chunk.ChunkCollection`, or
            ``None`` if none has been saved for ``source_path``.

        Raises:
            OSError: Implementations propagate or wrap the underlying
                I/O failure; see the concrete adapter's own docstring
                for the exact exception type it raises.
        """
        raise NotImplementedError
