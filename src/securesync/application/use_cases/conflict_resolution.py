"""Use cases for detecting and resolving synchronization conflicts."""

from __future__ import annotations

import uuid

import structlog

from securesync.domain.conflict import (
    ConflictMetadata,
    ConflictRepository,
    ConflictType,
    MergeStrategy,
    VersionVector,
)
from securesync.domain.conflict_exceptions import ConflictNotFoundError

logger = structlog.get_logger()


class LastWriterWinsStrategy:
    """A simple merge strategy that favors the version with the most recent timestamp."""

    def merge(self, local: ConflictMetadata, remote: ConflictMetadata) -> bool:
        """Remote wins if it was detected later (proxy for modification time)."""
        return remote.detected_at > local.detected_at


class DetectConflictUseCase:
    """Orchestrates conflict detection between local and remote versions."""

    def __init__(self, repository: ConflictRepository) -> None:
        self._repository = repository

    async def execute(
        self,
        file_path: str,
        local_version: VersionVector,
        remote_version: VersionVector,
        remote_device_id: str,
    ) -> ConflictMetadata | None:
        """Detect if a conflict exists and record it if so.

        Args:
            file_path: Path to the file being synced.
            local_version: Local version vector.
            remote_version: Remote version vector.
            remote_device_id: ID of the peer providing the remote version.

        Returns:
            A ConflictMetadata object if a conflict was detected, else None.
        """
        if local_version.is_concurrent(remote_version):
            conflict = ConflictMetadata(
                conflict_id=str(uuid.uuid4()),
                file_path=file_path,
                conflict_type=ConflictType.CONCURRENT_MODIFICATION,
                local_version=local_version,
                remote_version=remote_version,
                remote_device_id=remote_device_id,
            )
            await self._repository.save(conflict)
            logger.info(
                "conflict_detected",
                file_path=file_path,
                conflict_id=conflict.conflict_id,
                type=conflict.conflict_type,
            )
            return conflict
        return None


class ResolveConflictUseCase:
    """Orchestrates conflict resolution using a pluggable strategy."""

    def __init__(self, repository: ConflictRepository, strategy: MergeStrategy) -> None:
        self._repository = repository
        self._strategy = strategy

    async def execute(self, conflict_id: str, remote_metadata: ConflictMetadata) -> bool:
        """Resolve a conflict and mark it as resolved in the repository.

        Args:
            conflict_id: ID of the previously detected conflict.
            remote_metadata: The remote peer's version of the conflicting file.

        Returns:
            True if the remote version was chosen; False otherwise.

        Raises:
            ConflictNotFoundError: If no conflict with ``conflict_id``
                exists in the repository.
        """
        local_conflict = await self._repository.get_by_id(conflict_id)
        if not local_conflict:
            raise ConflictNotFoundError(f"Conflict {conflict_id} not found")

        remote_wins = self._strategy.merge(local_conflict, remote_metadata)
        await self._repository.resolve(conflict_id)

        logger.info("conflict_resolved", conflict_id=conflict_id, remote_wins=remote_wins)
        return remote_wins
