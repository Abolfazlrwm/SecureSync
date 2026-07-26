"""Domain entities and value objects for content chunking.

Everything in this module is pure Python: no filesystem I/O, no
hashing library import, no third-party dependency. Concrete
infrastructure adapters (a streaming file reader, a ``hashlib``-based
hasher) produce and consume these value objects; the domain itself has
no knowledge of how a chunk's bytes were read or how its hash was
computed.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum, unique
from pathlib import Path


@unique
class ChunkAlgorithm(StrEnum):
    """The digest algorithm used to hash a chunk's content.

    Only :attr:`SHA256` is implemented in Phase 2. The enum exists so a
    future algorithm (e.g. BLAKE3) can be added as a new member,
    without changing the shape of :class:`ChunkHash` or any code that
    depends on it (Open/Closed).
    """

    SHA256 = "sha256"


_DIGEST_HEX_LENGTH: dict[ChunkAlgorithm, int] = {
    ChunkAlgorithm.SHA256: 64,
}


@dataclass(frozen=True, slots=True)
class ChunkHash:
    """An immutable digest of a chunk's content.

    Attributes:
        algorithm: Which digest algorithm produced ``digest``.
        digest: The lowercase hexadecimal digest string.
    """

    algorithm: ChunkAlgorithm
    digest: str

    def __post_init__(self) -> None:
        """Validate that ``digest`` is well-formed hex for ``algorithm``.

        Raises:
            ValueError: If ``digest`` is empty, contains non-hexadecimal
                characters, or its length doesn't match the digest size
                expected for ``algorithm``.
        """
        if not self.digest:
            raise ValueError("digest must not be empty")
        try:
            int(self.digest, 16)
        except ValueError as exc:
            raise ValueError(f"digest is not valid hexadecimal: {self.digest!r}") from exc
        expected_length = _DIGEST_HEX_LENGTH[self.algorithm]
        if len(self.digest) != expected_length:
            raise ValueError(
                f"{self.algorithm.value} digest must be {expected_length} hex "
                f"characters, got {len(self.digest)}"
            )

    def __str__(self) -> str:
        """Render as ``algorithm:digest`` (e.g. ``sha256:abcd...``)."""
        return f"{self.algorithm.value}:{self.digest}"


@dataclass(frozen=True, slots=True)
class ChunkMetadata:
    """Descriptive metadata for a single chunk, independent of its bytes.

    Deliberately holds no chunk data itself, so a collection of many
    ``ChunkMetadata`` records (see :class:`ChunkCollection`) costs
    memory proportional to chunk *count*, never chunk *content*.

    Attributes:
        chunk_id: A stable identifier for this chunk, unique within its
            source file. Deterministically derived from the source
            file's identity and :attr:`index` (not a random UUID), so
            re-chunking the same file with the same strategy reproduces
            identical IDs — useful for idempotent re-runs, caching, and
            reproducible tests. This is a *local* identifier scoped to
            one file on one machine — it is derived from the source
            path string, so the "same" file at a different path (a
            different machine, a peer's copy) gets a different
            ``chunk_id``. Do not use it to recognize identical content
            across files or peers; that's what :attr:`chunk_hash` is
            for (a future Delta Sync / dedup phase compares
            ``chunk_hash`` values, never ``chunk_id`` values, across
            sources).
        index: The zero-based position of this chunk within the file.
        size: The number of bytes in this chunk.
        offset: The byte offset of this chunk's first byte within the
            original file.
        chunk_hash: The digest of this chunk's content, or ``None`` if
            it hasn't been computed yet (the state a
            :class:`~securesync.domain.chunking.ChunkReader` yields
            before a :class:`~securesync.domain.chunking.ChunkHasher`
            has run over the data). Content-addressable and portable —
            two chunks with identical bytes always have equal
            ``chunk_hash``, regardless of source file, path, or
            machine.
        created_at: The UTC instant this metadata was constructed.
    """

    chunk_id: str
    index: int
    size: int
    offset: int
    chunk_hash: ChunkHash | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        """Validate structural invariants.

        Raises:
            ValueError: If ``chunk_id`` is empty, or ``index``,
                ``size``, or ``offset`` is negative.
        """
        if not self.chunk_id:
            raise ValueError("chunk_id must not be empty")
        if self.index < 0:
            raise ValueError(f"index must be >= 0, got {self.index}")
        if self.size < 0:
            raise ValueError(f"size must be >= 0, got {self.size}")
        if self.offset < 0:
            raise ValueError(f"offset must be >= 0, got {self.offset}")

    def with_hash(self, chunk_hash: ChunkHash) -> ChunkMetadata:
        """Return a copy of this metadata with ``chunk_hash`` populated.

        Args:
            chunk_hash: The computed digest to attach.

        Returns:
            A new :class:`ChunkMetadata`; this instance is left
            unchanged, per the value object's immutability.
        """
        return replace(self, chunk_hash=chunk_hash)


@dataclass(frozen=True, slots=True)
class Chunk:
    """A chunk's metadata paired with its raw content.

    ``data`` is the only field able to hold a meaningful amount of
    memory — everything else is small, fixed-size metadata. Code that
    only needs a manifest (no bytes) should collect the ``metadata``
    of each ``Chunk`` instead of retaining ``Chunk`` instances
    themselves, so chunk-sized allocations aren't held longer than
    necessary — see :class:`ChunkCollection`.

    Attributes:
        metadata: This chunk's descriptive metadata.
        data: The chunk's raw bytes. Always exactly ``metadata.size``
            bytes long.
    """

    metadata: ChunkMetadata
    data: bytes

    def __post_init__(self) -> None:
        """Validate that ``data``'s length matches ``metadata.size``.

        Raises:
            ValueError: If ``len(data) != metadata.size``.
        """
        if len(self.data) != self.metadata.size:
            raise ValueError(
                f"data length ({len(self.data)}) does not match "
                f"metadata.size ({self.metadata.size})"
            )

    def with_hash(self, chunk_hash: ChunkHash) -> Chunk:
        """Return a copy of this chunk with its metadata hash populated.

        Args:
            chunk_hash: The computed digest to attach.

        Returns:
            A new :class:`Chunk` sharing the same ``data``; this
            instance is left unchanged.
        """
        return replace(self, metadata=self.metadata.with_hash(chunk_hash))


@dataclass(frozen=True, slots=True)
class ChunkCollection:
    """An ordered, complete manifest of one file's chunk metadata.

    Holds only :class:`ChunkMetadata` records — never chunk bytes — so
    a manifest for a multi-hundred-gigabyte file costs only as much
    memory as its chunk *count* (at most a few hundred thousand small
    records for any realistic chunk size), never its chunk *content*.

    Attributes:
        source_path: The path of the file this manifest describes.
        chunk_size: The chunking strategy's nominal chunk size, in
            bytes (the final chunk may be smaller).
        total_size: The total size, in bytes, of the source file.
        chunks: The chunk metadata, in ascending
            :attr:`ChunkMetadata.index` order.
    """

    source_path: Path
    chunk_size: int
    total_size: int
    chunks: tuple[ChunkMetadata, ...]

    def __post_init__(self) -> None:
        """Validate structural invariants across the whole collection.

        Raises:
            ValueError: If ``chunk_size`` isn't positive, ``total_size``
                is negative, chunk indices aren't a contiguous
                ``0..len(chunks)-1`` sequence, or the sum of chunk
                sizes doesn't equal ``total_size``.
        """
        if self.chunk_size <= 0:
            raise ValueError(f"chunk_size must be > 0, got {self.chunk_size}")
        if self.total_size < 0:
            raise ValueError(f"total_size must be >= 0, got {self.total_size}")
        for expected_index, chunk in enumerate(self.chunks):
            if chunk.index != expected_index:
                raise ValueError(
                    "chunks must be contiguously indexed from 0; expected index "
                    f"{expected_index}, got {chunk.index}"
                )
        actual_total = sum(chunk.size for chunk in self.chunks)
        if actual_total != self.total_size:
            raise ValueError(
                f"sum of chunk sizes ({actual_total}) does not match "
                f"total_size ({self.total_size})"
            )

    @property
    def chunk_count(self) -> int:
        """The number of chunks in this collection."""
        return len(self.chunks)
