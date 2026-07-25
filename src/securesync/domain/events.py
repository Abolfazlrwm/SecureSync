"""Domain events describing filesystem changes.

Everything in this module is pure Python: no filesystem I/O, no
third-party dependency (in particular, no ``watchdog`` import). Concrete
infrastructure adapters translate whatever low-level events their
underlying technology produces into instances of :class:`FileSystemEvent`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, unique
from pathlib import Path


@unique
class FileSystemEventType(StrEnum):
    """The kind of change observed on the filesystem.

    Renames are represented as :attr:`MOVED` with ``src_path`` and
    ``dest_path`` sharing the same parent directory; see
    :attr:`FileSystemEvent.is_rename`.
    """

    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    MOVED = "moved"


@dataclass(frozen=True, slots=True)
class FileSystemEvent:
    """An immutable record of a single filesystem change.

    Attributes:
        event_type: The kind of change that occurred.
        src_path: The path the change was observed on. For a
            :attr:`FileSystemEventType.MOVED` event, this is the original
            (pre-move) path.
        is_directory: Whether the affected filesystem entry is a
            directory rather than a file.
        timestamp: The UTC instant the event was constructed.
        dest_path: For :attr:`FileSystemEventType.MOVED` events, the
            destination path. ``None`` for every other event type.
    """

    event_type: FileSystemEventType
    src_path: Path
    is_directory: bool
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    dest_path: Path | None = None

    def __post_init__(self) -> None:
        """Validate that ``dest_path`` is present only for MOVED events.

        Raises:
            ValueError: If ``dest_path`` is missing on a MOVED event, or
                present on any other event type.
        """
        if self.event_type is FileSystemEventType.MOVED and self.dest_path is None:
            raise ValueError("dest_path is required for MOVED events")
        if self.event_type is not FileSystemEventType.MOVED and self.dest_path is not None:
            raise ValueError("dest_path is only valid for MOVED events")

    @property
    def is_rename(self) -> bool:
        """Whether a MOVED event is a rename rather than a relocation.

        Returns:
            ``True`` if this is a MOVED event whose source and
            destination share the same parent directory (a rename in
            place); ``False`` for cross-directory moves and for any
            non-MOVED event.
        """
        if self.event_type is not FileSystemEventType.MOVED or self.dest_path is None:
            return False
        return self.src_path.parent == self.dest_path.parent

    @property
    def dedup_key(self) -> tuple[str, str, str]:
        """A stable key identifying duplicate notifications of this event.

        Returns:
            A tuple of ``(event_type, src_path, dest_path)`` (the last
            element empty for non-MOVED events) suitable for use as a
            debounce cache key.
        """
        return (
            self.event_type.value,
            str(self.src_path),
            str(self.dest_path) if self.dest_path is not None else "",
        )
