"""Unit tests for `securesync.infrastructure.filesystem.event_translator`.

Constructs `watchdog` event objects directly (no real filesystem I/O
involved) so the translation logic is verified in isolation.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from watchdog.events import (
    DirCreatedEvent,
    DirDeletedEvent,
    DirMovedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
)

from securesync.domain.events import FileSystemEventType
from securesync.infrastructure.filesystem.event_translator import is_ignorable_event_type, translate


class TestTranslateBasicEvents:
    """Tests for translating create/modify/delete events."""

    def test_translates_file_created_event(self) -> None:
        """A `FileCreatedEvent` becomes a domain CREATED event on a file."""
        raw = FileCreatedEvent("/watched/new.txt")
        event = translate(raw)
        assert event.event_type is FileSystemEventType.CREATED
        assert event.src_path == Path("/watched/new.txt")
        assert event.is_directory is False
        assert event.dest_path is None

    def test_translates_file_modified_event(self) -> None:
        """A `FileModifiedEvent` becomes a domain MODIFIED event."""
        raw = FileModifiedEvent("/watched/existing.txt")
        event = translate(raw)
        assert event.event_type is FileSystemEventType.MODIFIED
        assert event.src_path == Path("/watched/existing.txt")

    def test_translates_file_deleted_event(self) -> None:
        """A `FileDeletedEvent` becomes a domain DELETED event."""
        raw = FileDeletedEvent("/watched/gone.txt")
        event = translate(raw)
        assert event.event_type is FileSystemEventType.DELETED
        assert event.src_path == Path("/watched/gone.txt")

    def test_translates_directory_created_event(self) -> None:
        """Directory events preserve `is_directory=True`."""
        raw = DirCreatedEvent("/watched/subdir")
        event = translate(raw)
        assert event.event_type is FileSystemEventType.CREATED
        assert event.is_directory is True

    def test_translates_directory_deleted_event(self) -> None:
        """Directory deletions preserve `is_directory=True`."""
        raw = DirDeletedEvent("/watched/subdir")
        event = translate(raw)
        assert event.event_type is FileSystemEventType.DELETED
        assert event.is_directory is True


class TestTranslateMovedEvents:
    """Tests for translating move/rename events."""

    def test_translates_file_moved_event_with_dest_path(self) -> None:
        """A `FileMovedEvent` carries both src_path and dest_path."""
        raw = FileMovedEvent("/watched/old.txt", "/watched/new.txt")
        event = translate(raw)
        assert event.event_type is FileSystemEventType.MOVED
        assert event.src_path == Path("/watched/old.txt")
        assert event.dest_path == Path("/watched/new.txt")

    def test_translates_directory_moved_event(self) -> None:
        """A `DirMovedEvent` is translated with `is_directory=True`."""
        raw = DirMovedEvent("/watched/old_dir", "/watched/new_dir")
        event = translate(raw)
        assert event.event_type is FileSystemEventType.MOVED
        assert event.is_directory is True
        assert event.dest_path == Path("/watched/new_dir")

    def test_rename_in_place_is_detected(self) -> None:
        """A move within the same parent directory is a rename."""
        raw = FileMovedEvent("/watched/old_name.txt", "/watched/new_name.txt")
        event = translate(raw)
        assert event.is_rename is True

    def test_move_across_directories_is_not_a_rename(self) -> None:
        """A move to a different parent directory isn't a rename."""
        raw = FileMovedEvent("/watched/a/file.txt", "/watched/b/file.txt")
        event = translate(raw)
        assert event.is_rename is False


class TestTranslateUnrecognizedEvent:
    """Tests for the failure path when an event type isn't recognized."""

    def test_unrecognized_event_type_raises_value_error(self) -> None:
        """An event with an unmapped `event_type` raises `ValueError`."""

        class _BogusRawEvent:
            event_type = "closed"
            src_path = "/watched/file.txt"
            dest_path = ""
            is_directory = False

        with pytest.raises(ValueError, match="Unrecognized watchdog event type"):
            translate(_BogusRawEvent())  # type: ignore[arg-type]


class TestIsIgnorableEventType:
    """Tests for `is_ignorable_event_type`."""

    @pytest.mark.parametrize("raw_type", ["opened", "closed", "closed_no_write"])
    def test_known_noise_types_are_ignorable(self, raw_type: str) -> None:
        """File open/close notifications are known, expected, and ignorable."""
        assert is_ignorable_event_type(raw_type) is True

    @pytest.mark.parametrize("raw_type", ["created", "modified", "deleted", "moved"])
    def test_mapped_types_are_not_ignorable(self, raw_type: str) -> None:
        """Types `translate` actually maps are never classified as ignorable."""
        assert is_ignorable_event_type(raw_type) is False

    def test_genuinely_unknown_type_is_not_ignorable(self) -> None:
        """A type that's neither mapped nor known noise is not ignorable.

        This is what lets callers log it loudly instead of silently -
        forward-compatible if `watchdog` ever adds a new event type.
        """
        assert is_ignorable_event_type("some_future_watchdog_event_type") is False
