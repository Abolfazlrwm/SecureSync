"""Unit tests for `securesync.domain.watcher`."""

from __future__ import annotations

from pathlib import Path

import pytest

from securesync.domain.events import FileSystemEvent, FileSystemEventType
from securesync.domain.watcher import FileSystemEventObserver, FileWatcher


class TestFileWatcherPort:
    """Tests for the `FileWatcher` abstract port."""

    def test_cannot_instantiate_directly(self) -> None:
        """`FileWatcher` is an ABC and cannot be instantiated on its own."""
        with pytest.raises(TypeError):
            FileWatcher()  # type: ignore[abstract]

    def test_incomplete_subclass_cannot_be_instantiated(self) -> None:
        """A subclass missing an abstract method still cannot be instantiated."""

        class IncompleteWatcher(FileWatcher):
            async def start(self) -> None:  # pragma: no cover - never reached
                pass

            async def stop(self) -> None:  # pragma: no cover - never reached
                pass

            def subscribe(self, observer: FileSystemEventObserver) -> None:
                pass

            # unsubscribe() and is_running are intentionally not implemented.

        with pytest.raises(TypeError):
            IncompleteWatcher()  # type: ignore[abstract]

    def test_complete_subclass_can_be_instantiated(self) -> None:
        """A subclass implementing every abstract member can be instantiated."""

        class MinimalWatcher(FileWatcher):
            def __init__(self) -> None:
                self._running = False

            async def start(self) -> None:
                self._running = True

            async def stop(self) -> None:
                self._running = False

            def subscribe(self, observer: FileSystemEventObserver) -> None:
                pass

            def unsubscribe(self, observer: FileSystemEventObserver) -> None:
                pass

            @property
            def is_running(self) -> bool:
                return self._running

        watcher = MinimalWatcher()
        assert watcher.is_running is False


class TestFileSystemEventObserverProtocol:
    """Tests for the `FileSystemEventObserver` structural protocol."""

    async def test_matching_object_satisfies_protocol(self) -> None:
        """Any object with a compatible `on_file_event` satisfies the protocol."""

        class Observer:
            def __init__(self) -> None:
                self.seen: list[FileSystemEvent] = []

            async def on_file_event(self, event: FileSystemEvent) -> None:
                self.seen.append(event)

        observer = Observer()
        assert isinstance(observer, FileSystemEventObserver)

        event = FileSystemEvent(
            event_type=FileSystemEventType.CREATED,
            src_path=Path("/watched/file.txt"),
            is_directory=False,
        )
        await observer.on_file_event(event)
        assert observer.seen == [event]

    def test_non_matching_object_does_not_satisfy_protocol(self) -> None:
        """An object without `on_file_event` does not satisfy the protocol."""

        class NotAnObserver:
            pass

        assert not isinstance(NotAnObserver(), FileSystemEventObserver)
