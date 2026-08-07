"""Domain entities and pure logic for delta synchronization.

Everything in this module is pure Python: no filesystem I/O, no
network code, no third-party dependency. Given two
:class:`~securesync.domain.chunk.ChunkCollection` manifests (a
previously recorded *baseline* and a freshly computed *current* one),
:class:`DeltaCalculator` decides, per chunk, whether its bytes must be
transferred or can be reused from what the baseline already
establishes as known content — see
``docs/adr/0009-content-addressable-delta-computation.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, unique
from pathlib import Path

from securesync.domain.chunk import ChunkCollection, ChunkHash, ChunkMetadata
from securesync.domain.delta_exceptions import IncompatibleBaselineError, UnhashedChunkError


@unique
class ChunkAction(StrEnum):
    """What must happen with one chunk of the *current* manifest.

    Attributes:
        TRANSFER: This chunk's content digest was not found anywhere
            in the baseline manifest — its bytes are not yet known to
            be available on the other end and must be sent.
        REUSE: A chunk with an identical content digest already
            exists in the baseline manifest (at any index — content is
            matched by hash, not position), so its bytes never need to
            be retransmitted.
    """

    TRANSFER = "transfer"
    REUSE = "reuse"


@dataclass(frozen=True, slots=True)
class ChunkDeltaEntry:
    """The classification of a single chunk of the *current* manifest.

    Attributes:
        metadata: The current chunk's metadata (always carries a
            populated ``chunk_hash`` — see :class:`DeltaCalculator`).
        action: Whether this chunk must be transferred or can be
            reused from the baseline.
    """

    metadata: ChunkMetadata
    action: ChunkAction


@dataclass(frozen=True, slots=True)
class DeltaPlan:
    """The complete result of diffing a *current* manifest against a baseline.

    Attributes:
        source_path: The file both manifests describe.
        baseline: The previously recorded manifest this plan was
            diffed against, or ``None`` if there was no baseline (the
            first time this file has ever been synced — every chunk is
            necessarily :attr:`ChunkAction.TRANSFER` in that case).
        current: The freshly computed manifest the plan describes.
        entries: One :class:`ChunkDeltaEntry` per chunk of
            :attr:`current`, in the same ascending index order as
            ``current.chunks``.
    """

    source_path: Path
    baseline: ChunkCollection | None
    current: ChunkCollection
    entries: tuple[ChunkDeltaEntry, ...]

    @property
    def chunks_to_transfer(self) -> tuple[ChunkMetadata, ...]:
        """The metadata of every chunk that must actually be transferred."""
        return tuple(
            entry.metadata for entry in self.entries if entry.action is ChunkAction.TRANSFER
        )

    @property
    def transfer_count(self) -> int:
        """How many of :attr:`current`'s chunks must be transferred."""
        return len(self.chunks_to_transfer)

    @property
    def reuse_count(self) -> int:
        """How many of :attr:`current`'s chunks can be reused from the baseline."""
        return self.current.chunk_count - self.transfer_count

    @property
    def bytes_to_transfer(self) -> int:
        """The total byte size of every chunk that must be transferred."""
        return sum(metadata.size for metadata in self.chunks_to_transfer)

    @property
    def is_first_sync(self) -> bool:
        """Whether this plan was computed with no prior baseline."""
        return self.baseline is None

    @property
    def has_changes(self) -> bool:
        """Whether at least one chunk must actually be transferred.

        ``False`` for an unchanged file (including an empty file with
        no baseline — there is nothing to transfer either way).
        """
        return self.transfer_count > 0


class DeltaCalculator:
    """Computes a :class:`DeltaPlan` by comparing chunk content digests.

    Stateless domain service — matching is purely a function of the
    two manifests given to :meth:`compute`, never any instance state.
    Chunks are matched by :attr:`~securesync.domain.chunk.ChunkMetadata.chunk_hash`
    across the *entire* baseline, not by index: a chunk that kept the
    same bytes but moved to a different position (e.g. content
    inserted earlier in the file) is still recognized as reusable, and
    matching stays correct regardless of which
    :class:`~securesync.domain.chunking.ChunkingStrategy` produced
    either manifest — see ADR-0009.
    """

    def compute(self, baseline: ChunkCollection | None, current: ChunkCollection) -> DeltaPlan:
        """Diff ``current`` against ``baseline``.

        Args:
            baseline: The previously recorded manifest for this file,
                typically loaded from a
                :class:`~securesync.domain.chunking.ChunkRepository`,
                or ``None`` if this file has never been synced before.
            current: The freshly computed manifest to classify. Every
                chunk must already carry a populated ``chunk_hash``.

        Returns:
            A :class:`DeltaPlan` with one entry per chunk of
            ``current``, in the same order.

        Raises:
            IncompatibleBaselineError: If ``baseline`` is not ``None``
                and describes a different ``source_path`` than
                ``current``.
            UnhashedChunkError: If any chunk in ``current`` has no
                recorded ``chunk_hash``.
        """
        if baseline is not None and baseline.source_path != current.source_path:
            raise IncompatibleBaselineError(
                f"cannot diff manifest for {current.source_path!r} against a "
                f"baseline recorded for {baseline.source_path!r}"
            )

        known_hashes = self._known_hashes(baseline)
        entries = tuple(
            ChunkDeltaEntry(
                metadata=metadata,
                action=(
                    ChunkAction.REUSE
                    if self._require_hash(metadata) in known_hashes
                    else ChunkAction.TRANSFER
                ),
            )
            for metadata in current.chunks
        )
        return DeltaPlan(
            source_path=current.source_path,
            baseline=baseline,
            current=current,
            entries=entries,
        )

    @staticmethod
    def _known_hashes(baseline: ChunkCollection | None) -> frozenset[ChunkHash]:
        """Collect every distinct content digest recorded in ``baseline``."""
        if baseline is None:
            return frozenset()
        return frozenset(
            chunk.chunk_hash for chunk in baseline.chunks if chunk.chunk_hash is not None
        )

    @staticmethod
    def _require_hash(metadata: ChunkMetadata) -> ChunkHash:
        """Return ``metadata.chunk_hash``, raising if it hasn't been computed.

        Raises:
            UnhashedChunkError: If ``metadata.chunk_hash`` is ``None``.
        """
        if metadata.chunk_hash is None:
            raise UnhashedChunkError(
                f"chunk {metadata.chunk_id} (index {metadata.index}) has no "
                "recorded hash; delta computation requires every current "
                "chunk to already be hashed"
            )
        return metadata.chunk_hash
