"""Integration tests: application use case + real infrastructure adapter.

These tests wire `MonitorDirectoriesUseCase` (application layer) to a
real `WatchdogFileWatcher` (infrastructure layer) against real temporary
directories, verifying the two layers cooperate correctly end-to-end -
composition-root-style dependency injection, exactly as a future
presentation layer would do it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from securesync.application.observers.logging_observer import LoggingFileSystemEventObserver
from securesync.application.use_cases.monitor_directories import MonitorDirectoriesUseCase
from securesync.domain.events import FileSystemEvent, FileSystemEventType
from securesync.infrastructure.filesystem.watchdog_watcher import WatchdogFileWatcher
from tests.doubles import CollectingObserver

EVENT_TIMEOUT = 5.0


def _has_event(event_type: FileSystemEventType, path: Path):  # type: ignore[no-untyped-def]
    """Build a predicate matching an event of `event_type` at `path`."""

    def _predicate(events: list[FileSystemEvent]) -> bool:
        return any(e.event_type is event_type and e.src_path == path for e in events)

    return _predicate


class TestMonitorDirectoriesIntegration:
    """End-to-end tests through the use case, injected with a real watcher."""

    async def test_use_case_delivers_real_events_to_observer(self, tmp_path: Path) -> None:
        """A file created after `start()` reaches the observer through the full stack."""
        watcher = WatchdogFileWatcher([tmp_path], debounce_seconds=0.0)
        use_case = MonitorDirectoriesUseCase(watcher)
        observer = CollectingObserver()
        use_case.register_observer(observer)

        await use_case.start()
        try:
            target = tmp_path / "integration_file.txt"
            target.write_text("hello from integration test")

            await observer.wait_until(
                _has_event(FileSystemEventType.CREATED, target), timeout_seconds=EVENT_TIMEOUT
            )
        finally:
            await use_case.stop()

    async def test_async_context_manager_lifecycle_with_real_watcher(self, tmp_path: Path) -> None:
        """The use case's `async with` starts and gracefully stops a real watcher."""
        watcher = WatchdogFileWatcher([tmp_path], debounce_seconds=0.0)
        observer = CollectingObserver()

        async with MonitorDirectoriesUseCase(watcher) as use_case:
            use_case.register_observer(observer)
            assert use_case.is_running is True

            target = tmp_path / "context_manager_file.txt"
            target.write_text("data")
            await observer.wait_until(
                _has_event(FileSystemEventType.CREATED, target), timeout_seconds=EVENT_TIMEOUT
            )

        assert use_case.is_running is False
        assert watcher.is_running is False

    async def test_multiple_directories_through_the_use_case(self, tmp_path: Path) -> None:
        """The use case correctly reports events from several injected directories."""
        dir_a = tmp_path / "dir_a"
        dir_b = tmp_path / "dir_b"
        dir_a.mkdir()
        dir_b.mkdir()
        file_a = dir_a / "a.txt"
        file_b = dir_b / "b.txt"

        watcher = WatchdogFileWatcher([dir_a, dir_b], debounce_seconds=0.0)
        use_case = MonitorDirectoriesUseCase(watcher)
        observer = CollectingObserver()
        use_case.register_observer(observer)

        async with use_case:
            file_a.write_text("a")
            file_b.write_text("b")

            def _both_created(events: list[FileSystemEvent]) -> bool:
                created = {
                    e.src_path for e in events if e.event_type is FileSystemEventType.CREATED
                }
                return file_a in created and file_b in created

            await observer.wait_until(_both_created, timeout_seconds=EVENT_TIMEOUT)

    async def test_logging_observer_does_not_crash_the_pipeline(self, tmp_path: Path) -> None:
        """The reference `LoggingFileSystemEventObserver` works end-to-end too."""
        watcher = WatchdogFileWatcher([tmp_path], debounce_seconds=0.0)
        use_case = MonitorDirectoriesUseCase(watcher)
        use_case.register_observer(LoggingFileSystemEventObserver())

        # Also register a collecting observer so the test can synchronize
        # on a real, awaited condition instead of a fixed sleep.
        observer = CollectingObserver()
        use_case.register_observer(observer)

        async with use_case:
            target = tmp_path / "logged_file.txt"
            target.write_text("data")
            await observer.wait_until(
                _has_event(FileSystemEventType.CREATED, target), timeout_seconds=EVENT_TIMEOUT
            )

    async def test_unregister_observer_through_the_use_case(self, tmp_path: Path) -> None:
        """`unregister_observer` on the use case stops further delivery."""
        watcher = WatchdogFileWatcher([tmp_path], debounce_seconds=0.0)
        use_case = MonitorDirectoriesUseCase(watcher)
        observer = CollectingObserver()
        use_case.register_observer(observer)

        async with use_case:
            first_file = tmp_path / "first.txt"
            first_file.write_text("x")
            await observer.wait_until(
                _has_event(FileSystemEventType.CREATED, first_file), timeout_seconds=EVENT_TIMEOUT
            )

            use_case.unregister_observer(observer)

            second_file = tmp_path / "second.txt"
            second_file.write_text("y")

            # Give the (now unsubscribed) observer a chance to wrongly
            # receive the event, then confirm it never did.
            await asyncio.sleep(0.5)
            paths = {e.src_path for e in observer.events}
            assert second_file not in paths
