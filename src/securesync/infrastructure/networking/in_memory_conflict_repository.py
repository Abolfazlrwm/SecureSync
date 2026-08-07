"""In-memory implementation of the ConflictRepository port."""

from __future__ import annotations

import asyncio

from securesync.domain.conflict import ConflictMetadata, ConflictRepository


class InMemoryConflictRepository(ConflictRepository):
    """A thread-safe in-memory store for conflicts."""

    def __init__(self) -> None:
        self._conflicts: dict[str, ConflictMetadata] = {}
        self._resolved: set[str] = set()
        self._lock = asyncio.Lock()

    async def save(self, conflict: ConflictMetadata) -> None:
        """See :meth:`ConflictRepository.save`."""
        async with self._lock:
            self._conflicts[conflict.conflict_id] = conflict

    async def get_by_id(self, conflict_id: str) -> ConflictMetadata | None:
        """See :meth:`ConflictRepository.get_by_id`."""
        async with self._lock:
            return self._conflicts.get(conflict_id)

    async def list_all(self) -> list[ConflictMetadata]:
        """List all conflicts (helper for testing)."""
        async with self._lock:
            return list(self._conflicts.values())

    async def list_active(self) -> list[ConflictMetadata]:
        """See :meth:`ConflictRepository.list_active`."""
        async with self._lock:
            return [c for c in self._conflicts.values() if c.conflict_id not in self._resolved]

    async def resolve(self, conflict_id: str) -> None:
        """See :meth:`ConflictRepository.resolve`."""
        async with self._lock:
            if conflict_id in self._conflicts:
                self._resolved.add(conflict_id)
