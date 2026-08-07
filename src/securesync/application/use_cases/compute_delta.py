"""Use case: compute a delta plan for a file against its recorded baseline."""

from __future__ import annotations

import asyncio
from pathlib import Path

import structlog

from securesync.application.use_cases.calculate_chunk_hashes import CalculateChunkHashesUseCase
from securesync.domain.chunking import ChunkingStrategy, ChunkRepository
from securesync.domain.delta import DeltaCalculator, DeltaPlan

logger = structlog.get_logger(__name__)


class ComputeDeltaUseCase:
    """Diffs a file's current chunks against the last manifest recorded for it.

    Composes an injected :class:`~securesync.domain.chunking.ChunkRepository`
    (the "chunk cache" — wherever the previous sync's manifest was
    saved) with
    :class:`~securesync.application.use_cases.calculate_chunk_hashes.CalculateChunkHashesUseCase`
    (computing the current manifest) and
    :class:`~securesync.domain.delta.DeltaCalculator` (the pure
    domain comparison). Read-only: it never mutates the repository.
    Persisting ``plan.current`` as the new baseline — normally done
    only after the chunks in ``plan.chunks_to_transfer`` have actually
    been transferred to a peer — is left to the caller via
    ``repository.save(plan.current)``, so a failed or partial transfer
    can never leave a baseline that overclaims what a peer has.
    """

    def __init__(
        self,
        chunk_hasher_use_case: CalculateChunkHashesUseCase,
        repository: ChunkRepository,
    ) -> None:
        """Initialize the use case.

        Args:
            chunk_hasher_use_case: Builds the current manifest.
                Injected by the composition root so this use case
                never constructs its own reader/hasher pair.
            repository: The chunk cache a previous sync's manifest was
                (or wasn't) saved to. Injected by the composition
                root.
        """
        self._chunk_hasher_use_case = chunk_hasher_use_case
        self._repository = repository
        self._calculator = DeltaCalculator()

    async def execute(
        self, path: Path, strategy: ChunkingStrategy, *, chunk_size: int
    ) -> DeltaPlan:
        """Compute the delta plan for ``path``.

        Args:
            path: The file to diff against its recorded baseline.
            strategy: Decides where each chunk boundary falls when
                computing the current manifest. Passing a different
                strategy than the one that produced the baseline is
                safe — chunks are matched by content hash, not
                position — though it naturally yields more
                :attr:`~securesync.domain.delta.ChunkAction.TRANSFER`
                entries, since a different boundary rule generally
                produces different chunk boundaries and thus different
                hashes for the same bytes.
            chunk_size: Recorded on the resulting current manifest;
                see :meth:`CalculateChunkHashesUseCase.build_manifest`.

        Returns:
            The computed :class:`~securesync.domain.delta.DeltaPlan`.

        Raises:
            ChunkSourceNotFoundError: If ``path`` doesn't exist.
            ChunkSourceAccessError: If ``path`` can't be read.
            ChunkEngineError: If the recorded baseline exists but
                can't be loaded from the repository.
        """
        baseline = await asyncio.to_thread(self._repository.load, path)
        current = await self._chunk_hasher_use_case.build_manifest(
            path, strategy, chunk_size=chunk_size
        )
        plan = self._calculator.compute(baseline, current)
        logger.info(
            "delta_computed",
            path=str(path),
            is_first_sync=plan.is_first_sync,
            transfer_count=plan.transfer_count,
            reuse_count=plan.reuse_count,
            bytes_to_transfer=plan.bytes_to_transfer,
        )
        return plan
