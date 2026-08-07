"""Domain entities and ports for metadata persistence.

This module defines the schema and repository port for storing file metadata,
peer information, and transfer history in a persistent store.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from securesync.domain.chunk import ChunkMetadata
from securesync.domain.conflict import VersionVector


@dataclass(frozen=True, slots=True)
class FileMetadata:
    """Metadata for a synchronized file.

    Attributes:
        file_path: Relative path to the file.
        version_vector: The current version vector for this file.
        last_modified: UTC timestamp of the last modification.
        is_deleted: Whether the file is marked as deleted (tombstone).
        chunks: List of chunk metadata composing the file.
    """

    file_path: str
    version_vector: VersionVector
    last_modified: datetime
    is_deleted: bool = False
    chunks: list[ChunkMetadata] = field(default_factory=list)


class MetadataRepository(ABC):
    """Port for persisting and querying system metadata."""

    @abstractmethod
    async def save_file_metadata(self, metadata: FileMetadata) -> None:
        """Save or update metadata for a file."""
        raise NotImplementedError

    @abstractmethod
    async def get_file_metadata(self, file_path: str) -> FileMetadata | None:
        """Retrieve metadata for a specific file path."""
        raise NotImplementedError

    @abstractmethod
    async def list_all_files(self) -> list[FileMetadata]:
        """Retrieve metadata for all known files."""
        raise NotImplementedError

    @abstractmethod
    async def delete_file_metadata(self, file_path: str) -> None:
        """Remove metadata for a file (or mark as deleted)."""
        raise NotImplementedError

    @abstractmethod
    async def begin_transaction(self) -> None:
        """Start a new database transaction."""
        raise NotImplementedError

    @abstractmethod
    async def commit(self) -> None:
        """Commit the current transaction."""
        raise NotImplementedError

    @abstractmethod
    async def rollback(self) -> None:
        """Roll back the current transaction."""
        raise NotImplementedError
