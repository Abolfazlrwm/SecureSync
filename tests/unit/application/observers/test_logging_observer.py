"""Unit tests for `securesync.application.observers.logging_observer`."""

from __future__ import annotations

from pathlib import Path

import structlog

from securesync.application.observers.logging_observer import LoggingFileSystemEventObserver
from securesync.domain.events import FileSystemEvent, FileSystemEventType
from securesync.domain.watcher import FileSystemEventObserver


class TestLoggingFileSystemEventObserver:
    """Tests for `LoggingFileSystemEventObserver`."""

    def test_satisfies_the_observer_protocol(self) -> None:
        """An instance structurally satisfies `FileSystemEventObserver`."""
        assert isinstance(LoggingFileSystemEventObserver(), FileSystemEventObserver)

    async def test_logs_a_created_event(self) -> None:
        """A CREATED event is logged with the expected structured fields."""
        observer = LoggingFileSystemEventObserver()
        event = FileSystemEvent(
            event_type=FileSystemEventType.CREATED,
            src_path=Path("/watched/new.txt"),
            is_directory=False,
        )

        with structlog.testing.capture_logs() as captured:
            await observer.on_file_event(event)

        assert len(captured) == 1
        entry = captured[0]
        assert entry["event"] == "filesystem_event"
        assert entry["event_type"] == "created"
        assert entry["path"] == "/watched/new.txt"
        assert entry["dest_path"] is None
        assert entry["is_directory"] is False
        assert entry["is_rename"] is False

    async def test_logs_a_moved_event_with_dest_path(self) -> None:
        """A MOVED event's log entry includes the destination path."""
        observer = LoggingFileSystemEventObserver()
        event = FileSystemEvent(
            event_type=FileSystemEventType.MOVED,
            src_path=Path("/watched/old.txt"),
            dest_path=Path("/watched/new.txt"),
            is_directory=False,
        )

        with structlog.testing.capture_logs() as captured:
            await observer.on_file_event(event)

        entry = captured[0]
        assert entry["dest_path"] == "/watched/new.txt"
        assert entry["is_rename"] is True
