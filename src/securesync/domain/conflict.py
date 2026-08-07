"""Domain entities and ports for Conflict Resolution.

This module defines the abstractions for version tracking and conflict
detection/resolution, isolated from concrete storage or network logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, unique
from typing import Protocol


@dataclass(frozen=True, slots=True)
class VersionVector:
    """A logical clock for tracking causal relationships between file versions.

    Attributes:
        counters: A mapping of device_id to its logical counter.
    """

    counters: dict[str, int] = field(default_factory=dict)

    def increment(self, device_id: str) -> VersionVector:
        """Return a new vector with the counter for device_id incremented."""
        new_counters = self.counters.copy()
        new_counters[device_id] = new_counters.get(device_id, 0) + 1
        return VersionVector(new_counters)

    def merge(self, other: VersionVector) -> VersionVector:
        """Return a new vector that is the element-wise maximum of two vectors."""
        new_counters = self.counters.copy()
        for device_id, counter in other.counters.items():
            new_counters[device_id] = max(new_counters.get(device_id, 0), counter)
        return VersionVector(new_counters)

    def is_concurrent(self, other: VersionVector) -> bool:
        """Whether this vector is concurrent with another (neither is a descendant)."""
        return not (self <= other or other <= self)

    def __le__(self, other: VersionVector) -> bool:
        """Whether this vector is less than or equal to another (ancestor or equal)."""
        for device_id, counter in self.counters.items():
            if counter > other.counters.get(device_id, 0):
                return False
        return True

    def __lt__(self, other: VersionVector) -> bool:
        """Whether this vector is strictly less than another (ancestor)."""
        return self <= other and self != other


@unique
class ConflictType(StrEnum):
    """The nature of a synchronization conflict."""

    CONCURRENT_MODIFICATION = "concurrent_modification"
    MODIFY_DELETE = "modify_delete"
    RENAME_CONFLICT = "rename_conflict"
    MOVE_CONFLICT = "move_conflict"


@dataclass(frozen=True, slots=True)
class ConflictMetadata:
    """Metadata describing a detected conflict.

    Attributes:
        conflict_id: Unique identifier for the conflict.
        file_path: The path where the conflict occurred.
        conflict_type: The type of conflict.
        detected_at: The UTC instant the conflict was detected.
        local_version: The version vector of the local file.
        remote_version: The version vector of the remote file.
        remote_device_id: The ID of the peer that sent the conflicting version.
    """

    conflict_id: str
    file_path: str
    conflict_type: ConflictType
    local_version: VersionVector
    remote_version: VersionVector
    remote_device_id: str
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class ConflictRepository(ABC):
    """Port for persisting and retrieving conflict information."""

    @abstractmethod
    async def save(self, conflict: ConflictMetadata) -> None:
        """Save a new conflict record."""
        raise NotImplementedError

    @abstractmethod
    async def get_by_id(self, conflict_id: str) -> ConflictMetadata | None:
        """Retrieve a conflict by its ID."""
        raise NotImplementedError

    @abstractmethod
    async def list_active(self) -> list[ConflictMetadata]:
        """List all unresolved conflicts."""
        raise NotImplementedError

    @abstractmethod
    async def resolve(self, conflict_id: str) -> None:
        """Mark a conflict as resolved."""
        raise NotImplementedError


class MergeStrategy(Protocol):
    """Abstraction for automatic conflict resolution policies."""

    def merge(self, local: ConflictMetadata, remote: ConflictMetadata) -> bool:
        """Decide whether to accept the remote version or keep the local one.

        Returns:
            True if the remote version wins; False if the local one wins.
        """
        ...
