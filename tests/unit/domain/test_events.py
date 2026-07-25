"""Unit tests for `securesync.domain.events`."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from securesync.domain.events import FileSystemEvent, FileSystemEventType


class TestFileSystemEventType:
    """Tests for the `FileSystemEventType` enum."""

    def test_values_match_expected_strings(self) -> None:
        """Each member's value is the lowercase name, used for logging/keys."""
        assert FileSystemEventType.CREATED.value == "created"
        assert FileSystemEventType.MODIFIED.value == "modified"
        assert FileSystemEventType.DELETED.value == "deleted"
        assert FileSystemEventType.MOVED.value == "moved"

    def test_members_are_unique(self) -> None:
        """The `@unique` decorator guarantees no aliasing; sanity-check count."""
        assert len(set(FileSystemEventType)) == 4


class TestFileSystemEventConstruction:
    """Tests for constructing `FileSystemEvent` instances."""

    def test_created_event_without_dest_path(self) -> None:
        """Non-MOVED events are constructible without a dest_path."""
        event = FileSystemEvent(
            event_type=FileSystemEventType.CREATED,
            src_path=Path("/watched/file.txt"),
            is_directory=False,
        )
        assert event.dest_path is None
        assert event.event_type is FileSystemEventType.CREATED

    def test_moved_event_requires_dest_path(self) -> None:
        """Constructing a MOVED event without dest_path raises ValueError."""
        with pytest.raises(ValueError, match="dest_path is required"):
            FileSystemEvent(
                event_type=FileSystemEventType.MOVED,
                src_path=Path("/watched/a.txt"),
                is_directory=False,
            )

    @pytest.mark.parametrize(
        "event_type",
        [FileSystemEventType.CREATED, FileSystemEventType.MODIFIED, FileSystemEventType.DELETED],
    )
    def test_non_moved_event_rejects_dest_path(self, event_type: FileSystemEventType) -> None:
        """Setting dest_path on a non-MOVED event raises ValueError."""
        with pytest.raises(ValueError, match="only valid for MOVED"):
            FileSystemEvent(
                event_type=event_type,
                src_path=Path("/watched/a.txt"),
                is_directory=False,
                dest_path=Path("/watched/b.txt"),
            )

    def test_timestamp_defaults_to_now_utc(self) -> None:
        """An unspecified timestamp defaults to the current UTC time."""
        before = datetime.now(UTC)
        event = FileSystemEvent(
            event_type=FileSystemEventType.CREATED,
            src_path=Path("/watched/file.txt"),
            is_directory=False,
        )
        after = datetime.now(UTC)
        assert before <= event.timestamp <= after

    def test_event_is_immutable(self) -> None:
        """`FileSystemEvent` is frozen; attribute assignment raises."""
        event = FileSystemEvent(
            event_type=FileSystemEventType.CREATED,
            src_path=Path("/watched/file.txt"),
            is_directory=False,
        )
        with pytest.raises(AttributeError):
            event.src_path = Path("/other.txt")  # type: ignore[misc]


class TestIsRename:
    """Tests for `FileSystemEvent.is_rename`."""

    def test_move_within_same_directory_is_rename(self) -> None:
        """Same parent directory => rename."""
        event = FileSystemEvent(
            event_type=FileSystemEventType.MOVED,
            src_path=Path("/watched/old.txt"),
            dest_path=Path("/watched/new.txt"),
            is_directory=False,
        )
        assert event.is_rename is True

    def test_move_across_directories_is_not_rename(self) -> None:
        """Different parent directories => move, not a rename."""
        event = FileSystemEvent(
            event_type=FileSystemEventType.MOVED,
            src_path=Path("/watched/sub_a/file.txt"),
            dest_path=Path("/watched/sub_b/file.txt"),
            is_directory=False,
        )
        assert event.is_rename is False

    def test_non_moved_event_is_never_a_rename(self) -> None:
        """`is_rename` is False for every non-MOVED event type."""
        event = FileSystemEvent(
            event_type=FileSystemEventType.CREATED,
            src_path=Path("/watched/file.txt"),
            is_directory=False,
        )
        assert event.is_rename is False


class TestDedupKey:
    """Tests for `FileSystemEvent.dedup_key`."""

    def test_dedup_key_for_non_moved_event(self) -> None:
        """The dest component of the key is empty for non-MOVED events."""
        event = FileSystemEvent(
            event_type=FileSystemEventType.MODIFIED,
            src_path=Path("/watched/file.txt"),
            is_directory=False,
        )
        assert event.dedup_key == ("modified", "/watched/file.txt", "")

    def test_dedup_key_for_moved_event_includes_dest(self) -> None:
        """The dest component of the key reflects dest_path for MOVED events."""
        event = FileSystemEvent(
            event_type=FileSystemEventType.MOVED,
            src_path=Path("/watched/old.txt"),
            dest_path=Path("/watched/new.txt"),
            is_directory=False,
        )
        assert event.dedup_key == ("moved", "/watched/old.txt", "/watched/new.txt")

    def test_identical_events_share_dedup_key(self) -> None:
        """Two separately constructed but logically-identical events match."""
        first = FileSystemEvent(
            event_type=FileSystemEventType.CREATED,
            src_path=Path("/watched/file.txt"),
            is_directory=False,
        )
        second = FileSystemEvent(
            event_type=FileSystemEventType.CREATED,
            src_path=Path("/watched/file.txt"),
            is_directory=False,
        )
        assert first.dedup_key == second.dedup_key
