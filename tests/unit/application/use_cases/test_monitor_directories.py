"""Unit tests for `securesync.application.use_cases.monitor_directories`."""

from __future__ import annotations

from pathlib import Path

import pytest

from securesync.application.use_cases.monitor_directories import MonitorDirectoriesUseCase
from securesync.domain.events import FileSystemEvent, FileSystemEventType
from tests.doubles import CollectingObserver, FailingObserver, FakeFileWatcher


class TestStartStop:
    """Tests for the start/stop delegation to the injected `FileWatcher`."""

    async def test_start_delegates_to_watcher(self) -> None:
        """`start()` calls through to `watcher.start()` exactly once."""
        watcher = FakeFileWatcher()
        use_case = MonitorDirectoriesUseCase(watcher)
        await use_case.start()
        assert watcher.start_calls == 1
        assert use_case.is_running is True

    async def test_stop_delegates_to_watcher(self) -> None:
        """`stop()` calls through to `watcher.stop()` exactly once."""
        watcher = FakeFileWatcher()
        use_case = MonitorDirectoriesUseCase(watcher)
        await use_case.start()
        await use_case.stop()
        assert watcher.stop_calls == 1
        assert use_case.is_running is False

    async def test_start_failure_propagates(self) -> None:
        """An error raised by the watcher on start propagates to the caller."""
        watcher = FakeFileWatcher()
        watcher.raise_on_start = RuntimeError("underlying watcher failed")
        use_case = MonitorDirectoriesUseCase(watcher)
        with pytest.raises(RuntimeError, match="underlying watcher failed"):
            await use_case.start()

    async def test_stop_failure_propagates(self) -> None:
        """An error raised by the watcher on stop propagates to the caller."""
        watcher = FakeFileWatcher()
        watcher.raise_on_stop = RuntimeError("underlying watcher failed to stop")
        use_case = MonitorDirectoriesUseCase(watcher)
        await use_case.start()
        with pytest.raises(RuntimeError, match="underlying watcher failed to stop"):
            await use_case.stop()


class TestObserverRegistration:
    """Tests for observer registration delegation."""

    async def test_register_observer_subscribes_on_watcher(self) -> None:
        """`register_observer` forwards to `watcher.subscribe`."""
        watcher = FakeFileWatcher()
        use_case = MonitorDirectoriesUseCase(watcher)
        observer = CollectingObserver()

        use_case.register_observer(observer)

        assert observer in watcher.observers

    async def test_unregister_observer_unsubscribes_on_watcher(self) -> None:
        """`unregister_observer` forwards to `watcher.unsubscribe`."""
        watcher = FakeFileWatcher()
        use_case = MonitorDirectoriesUseCase(watcher)
        observer = CollectingObserver()
        use_case.register_observer(observer)

        use_case.unregister_observer(observer)

        assert observer not in watcher.observers

    async def test_registered_observer_receives_emitted_events(self) -> None:
        """End-to-end (via the fake): a registered observer sees emitted events."""
        watcher = FakeFileWatcher()
        use_case = MonitorDirectoriesUseCase(watcher)
        observer = CollectingObserver()
        use_case.register_observer(observer)

        event = FileSystemEvent(
            event_type=FileSystemEventType.CREATED,
            src_path=Path("/watched/new.txt"),
            is_directory=False,
        )
        await watcher.emit(event)

        assert observer.events == [event]

    async def test_one_failing_observer_does_not_affect_bookkeeping(self) -> None:
        """A raising observer's failure is the fake watcher's concern, not ours.

        This exercises that `register_observer`/`unregister_observer` work
        uniformly regardless of what the observer does with an event.
        """
        watcher = FakeFileWatcher()
        use_case = MonitorDirectoriesUseCase(watcher)
        observer = FailingObserver()
        use_case.register_observer(observer)
        assert observer in watcher.observers
        use_case.unregister_observer(observer)
        assert observer not in watcher.observers


class TestAsyncContextManager:
    """Tests for using `MonitorDirectoriesUseCase` as an async context manager."""

    async def test_context_manager_starts_and_stops(self) -> None:
        """Entering starts monitoring; exiting stops it, even on success."""
        watcher = FakeFileWatcher()
        use_case = MonitorDirectoriesUseCase(watcher)

        async with use_case as ctx:
            assert ctx is use_case
            assert watcher.start_calls == 1
            assert use_case.is_running is True

        assert watcher.stop_calls == 1
        assert use_case.is_running is False

    async def test_context_manager_stops_even_when_body_raises(self) -> None:
        """Graceful shutdown happens even if the `async with` body raises."""
        watcher = FakeFileWatcher()
        use_case = MonitorDirectoriesUseCase(watcher)

        with pytest.raises(ValueError, match="boom"):
            async with use_case:
                raise ValueError("boom")

        assert watcher.stop_calls == 1
        assert use_case.is_running is False
