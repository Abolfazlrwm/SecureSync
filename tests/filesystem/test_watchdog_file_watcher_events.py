"""Real-filesystem, temp-directory tests for `WatchdogFileWatcher`.

Unlike `tests/unit/infrastructure/filesystem/test_watchdog_watcher.py`,
every test here performs actual filesystem operations against a real
`watchdog` observer and asserts that real OS-level notifications are
correctly translated and delivered.

A single filesystem operation commonly produces *more* than one raw
notification (for example, writing a file also touches its parent
directory's mtime, producing an extra MODIFIED event on the directory).
Tests therefore wait for a specific, precise condition via
`CollectingObserver.wait_until` rather than a raw event count, and
generous timeouts are used to avoid flakiness across platforms/backends
(inotify, FSEvents, ReadDirectoryChangesW).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Callable, Iterable
from pathlib import Path
from typing import Protocol

import pytest

from securesync.domain.events import FileSystemEvent, FileSystemEventType
from securesync.infrastructure.filesystem.watchdog_watcher import WatchdogFileWatcher
from tests.doubles import CollectingObserver, FailingObserver

EVENT_TIMEOUT = 5.0


def _has_event(
    event_type: FileSystemEventType, path: Path
) -> Callable[[list[FileSystemEvent]], bool]:
    """Build a predicate matching an event of `event_type` at `path`."""

    def _predicate(events: list[FileSystemEvent]) -> bool:
        return any(e.event_type is event_type and e.src_path == path for e in events)

    return _predicate


class WatcherFactory(Protocol):
    """Typed factory returned by the `watcher_factory` fixture."""

    def __call__(
        self,
        paths: Iterable[Path],
        *,
        recursive: bool = True,
        debounce_seconds: float = 0.5,
    ) -> WatchdogFileWatcher: ...


@pytest.fixture
async def watcher_factory() -> AsyncGenerator[WatcherFactory, None]:
    """Yield a factory for `WatchdogFileWatcher` instances, stopping them after the test.

    Ensures every watcher created during a test is gracefully stopped
    afterwards, even if the test body fails partway through.
    """
    created: list[WatchdogFileWatcher] = []

    def _make(
        paths: Iterable[Path],
        *,
        recursive: bool = True,
        debounce_seconds: float = 0.5,
    ) -> WatchdogFileWatcher:
        watcher = WatchdogFileWatcher(paths, recursive=recursive, debounce_seconds=debounce_seconds)
        created.append(watcher)
        return watcher

    yield _make

    for watcher in created:
        await watcher.stop()


class TestCreateModifyDelete:
    """Tests for basic create/modify/delete detection."""

    async def test_detects_file_creation(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """Creating a file inside a watched directory produces a CREATED event."""
        target = tmp_path / "new_file.txt"
        watcher = watcher_factory([tmp_path], debounce_seconds=0.0)
        observer = CollectingObserver()
        watcher.subscribe(observer)
        await watcher.start()

        target.write_text("hello")

        events = await observer.wait_until(
            _has_event(FileSystemEventType.CREATED, target), timeout_seconds=EVENT_TIMEOUT
        )
        created = next(
            e
            for e in events
            if e.event_type is FileSystemEventType.CREATED and e.src_path == target
        )
        assert created.is_directory is False

    async def test_detects_file_modification(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """Modifying an existing file produces a MODIFIED event."""
        target = tmp_path / "existing.txt"
        target.write_text("v1")

        watcher = watcher_factory([tmp_path], debounce_seconds=0.0)
        observer = CollectingObserver()
        watcher.subscribe(observer)
        await watcher.start()

        target.write_text("v2 - changed content")

        await observer.wait_until(
            _has_event(FileSystemEventType.MODIFIED, target), timeout_seconds=EVENT_TIMEOUT
        )

    async def test_detects_file_deletion(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """Deleting an existing file produces a DELETED event."""
        target = tmp_path / "to_delete.txt"
        target.write_text("bye")

        watcher = watcher_factory([tmp_path], debounce_seconds=0.0)
        observer = CollectingObserver()
        watcher.subscribe(observer)
        await watcher.start()

        target.unlink()

        await observer.wait_until(
            _has_event(FileSystemEventType.DELETED, target), timeout_seconds=EVENT_TIMEOUT
        )


class TestMoveAndRename:
    """Tests for move/rename detection."""

    async def test_detects_rename_in_place(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """Renaming a file within the same directory produces a MOVED, is_rename event."""
        original = tmp_path / "original_name.txt"
        original.write_text("content")

        watcher = watcher_factory([tmp_path], debounce_seconds=0.0)
        observer = CollectingObserver()
        watcher.subscribe(observer)
        await watcher.start()

        renamed = tmp_path / "renamed.txt"
        original.rename(renamed)

        events = await observer.wait_until(
            _has_event(FileSystemEventType.MOVED, original), timeout_seconds=EVENT_TIMEOUT
        )
        moved = next(e for e in events if e.event_type is FileSystemEventType.MOVED)
        assert moved.dest_path == renamed
        assert moved.is_rename is True

    async def test_detects_move_across_directories(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """Moving a file to a different watched directory is MOVED, not a rename."""
        src_dir = tmp_path / "src"
        dst_dir = tmp_path / "dst"
        src_dir.mkdir()
        dst_dir.mkdir()
        original = src_dir / "file.txt"
        original.write_text("content")

        watcher = watcher_factory([tmp_path], debounce_seconds=0.0)
        observer = CollectingObserver()
        watcher.subscribe(observer)
        await watcher.start()

        destination = dst_dir / "file.txt"
        original.rename(destination)

        events = await observer.wait_until(
            _has_event(FileSystemEventType.MOVED, original), timeout_seconds=EVENT_TIMEOUT
        )
        moved = next(e for e in events if e.event_type is FileSystemEventType.MOVED)
        assert moved.dest_path == destination
        assert moved.is_rename is False


class TestMultipleDirectories:
    """Tests for monitoring several independent directories at once."""

    async def test_events_from_all_watched_directories_are_captured(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """A single watcher instance reports events from every configured directory."""
        dir_a = tmp_path / "dir_a"
        dir_b = tmp_path / "dir_b"
        dir_a.mkdir()
        dir_b.mkdir()
        file_a = dir_a / "a.txt"
        file_b = dir_b / "b.txt"

        watcher = watcher_factory([dir_a, dir_b], debounce_seconds=0.0)
        observer = CollectingObserver()
        watcher.subscribe(observer)
        await watcher.start()

        file_a.write_text("a")
        file_b.write_text("b")

        def _both_created(events: list[FileSystemEvent]) -> bool:
            created = {e.src_path for e in events if e.event_type is FileSystemEventType.CREATED}
            return file_a in created and file_b in created

        await observer.wait_until(_both_created, timeout_seconds=EVENT_TIMEOUT)


class TestRecursiveMonitoring:
    """Tests for the `recursive` flag."""

    async def test_recursive_true_detects_nested_directory_events(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """With recursive=True, changes in subdirectories are detected."""
        nested = tmp_path / "level1" / "level2"
        nested.mkdir(parents=True)
        target = nested / "deep_file.txt"

        watcher = watcher_factory([tmp_path], recursive=True, debounce_seconds=0.0)
        observer = CollectingObserver()
        watcher.subscribe(observer)
        await watcher.start()

        target.write_text("deep")

        await observer.wait_until(
            _has_event(FileSystemEventType.CREATED, target), timeout_seconds=EVENT_TIMEOUT
        )

    async def test_recursive_false_ignores_nested_directory_events(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """With recursive=False, only the top-level directory is monitored."""
        nested = tmp_path / "level1"
        nested.mkdir()

        watcher = watcher_factory([tmp_path], recursive=False, debounce_seconds=0.0)
        observer = CollectingObserver()
        watcher.subscribe(observer)
        await watcher.start()

        # This top-level creation must still be observed.
        top_level = tmp_path / "top_level.txt"
        top_level.write_text("top")
        await observer.wait_until(
            _has_event(FileSystemEventType.CREATED, top_level), timeout_seconds=EVENT_TIMEOUT
        )

        # A nested creation must NOT be observed - give it a short grace
        # period, then assert no matching event ever arrived.
        nested_file = nested / "nested_file.txt"
        nested_file.write_text("nested")
        await asyncio.sleep(0.5)

        nested_paths = {e.src_path for e in observer.events}
        assert nested_file not in nested_paths


class TestDebounce:
    """Tests for suppressing duplicate rapid-fire events."""

    async def test_rapid_successive_writes_are_debounced(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """Several quick writes to the same file collapse into few MODIFIED events."""
        target = tmp_path / "hot_file.txt"
        target.write_text("v0")

        watcher = watcher_factory([tmp_path], debounce_seconds=1.0)
        observer = CollectingObserver()
        watcher.subscribe(observer)
        await watcher.start()

        for i in range(10):
            target.write_text(f"v{i}")

        # Let any in-flight notifications settle, then check the count.
        await asyncio.sleep(1.0)
        modified_on_target = [
            e
            for e in observer.events
            if e.event_type is FileSystemEventType.MODIFIED and e.src_path == target
        ]
        # Ten rapid writes within the 1s debounce window must collapse to
        # far fewer than 10 delivered events for this specific file.
        assert len(modified_on_target) < 10


class TestGracefulShutdown:
    """Tests for stop() behaving correctly against a live, real watcher."""

    async def test_stop_prevents_further_event_delivery(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """After stop(), further filesystem changes produce no new events."""
        before = tmp_path / "before_stop.txt"
        after = tmp_path / "after_stop.txt"

        watcher = watcher_factory([tmp_path], debounce_seconds=0.0)
        observer = CollectingObserver()
        watcher.subscribe(observer)
        await watcher.start()

        before.write_text("x")
        await observer.wait_until(
            _has_event(FileSystemEventType.CREATED, before), timeout_seconds=EVENT_TIMEOUT
        )

        await watcher.stop()
        assert watcher.is_running is False

        after.write_text("y")
        await asyncio.sleep(0.5)

        paths = {e.src_path for e in observer.events}
        assert after not in paths

    async def test_stop_is_safe_to_call_multiple_times(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """Calling stop() repeatedly on a real watcher never raises."""
        watcher = watcher_factory([tmp_path])
        await watcher.start()
        await watcher.stop()
        await watcher.stop()
        await watcher.stop()
        assert watcher.is_running is False


class TestMultipleObservers:
    """Tests for the Observer pattern with more than one subscriber."""

    async def test_all_subscribed_observers_receive_the_same_event(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """Every subscribed observer independently receives each event."""
        target = tmp_path / "shared_event.txt"
        watcher = watcher_factory([tmp_path], debounce_seconds=0.0)
        first = CollectingObserver()
        second = CollectingObserver()
        watcher.subscribe(first)
        watcher.subscribe(second)
        await watcher.start()

        target.write_text("x")

        await first.wait_until(
            _has_event(FileSystemEventType.CREATED, target), timeout_seconds=EVENT_TIMEOUT
        )
        await second.wait_until(
            _has_event(FileSystemEventType.CREATED, target), timeout_seconds=EVENT_TIMEOUT
        )

    async def test_unsubscribed_observer_stops_receiving_events(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """After unsubscribe, an observer receives no further events."""
        first_file = tmp_path / "first.txt"
        second_file = tmp_path / "second.txt"

        watcher = watcher_factory([tmp_path], debounce_seconds=0.0)
        observer = CollectingObserver()
        watcher.subscribe(observer)
        await watcher.start()

        first_file.write_text("x")
        await observer.wait_until(
            _has_event(FileSystemEventType.CREATED, first_file), timeout_seconds=EVENT_TIMEOUT
        )

        watcher.unsubscribe(observer)
        second_file.write_text("y")
        await asyncio.sleep(0.5)

        paths = {e.src_path for e in observer.events}
        assert second_file not in paths

    async def test_a_failing_observer_does_not_block_other_observers(
        self, tmp_path: Path, watcher_factory: WatcherFactory
    ) -> None:
        """One observer raising on every event must not stop delivery to others."""
        target = tmp_path / "watched_despite_failure.txt"
        watcher = watcher_factory([tmp_path], debounce_seconds=0.0)
        healthy = CollectingObserver()
        failing = FailingObserver()
        watcher.subscribe(failing)
        watcher.subscribe(healthy)
        await watcher.start()

        target.write_text("x")

        await healthy.wait_until(
            _has_event(FileSystemEventType.CREATED, target), timeout_seconds=EVENT_TIMEOUT
        )
        assert failing.call_count > 0
