"""Unit tests for `WatchdogFileWatcher` construction and lifecycle state.

These tests cover validation and state-machine behavior (double-start,
stop-when-not-started, subscribe/unsubscribe bookkeeping) plus the
error-handling paths around a real-but-mocked `watchdog` observer. End-to-
end tests that assert real filesystem events are actually detected live
in `tests/filesystem/`.
"""

from __future__ import annotations

from concurrent.futures import Future
from pathlib import Path
from unittest.mock import patch

import pytest
import structlog

from securesync.domain.events import FileSystemEvent, FileSystemEventType
from securesync.domain.exceptions import InvalidWatchTargetError, WatcherAlreadyRunningError
from securesync.infrastructure.filesystem.debounce import EventDebouncer
from securesync.infrastructure.filesystem.watchdog_watcher import (
    WatchdogFileWatcher,
    _DispatchingEventHandler,
)
from securesync.shared.exceptions import FileWatcherError
from tests.doubles import CollectingObserver


class TestConstruction:
    """Tests for `WatchdogFileWatcher.__init__`."""

    def test_requires_at_least_one_path(self) -> None:
        """Constructing with an empty path collection raises ValueError."""
        with pytest.raises(ValueError, match="At least one path must be provided"):
            WatchdogFileWatcher(paths=[])

    def test_not_running_before_start(self, tmp_path: Path) -> None:
        """A freshly constructed watcher reports `is_running` as False."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        assert watcher.is_running is False


class TestStartValidation:
    """Tests for path validation performed by `start()`."""

    async def test_missing_directory_raises(self, tmp_path: Path) -> None:
        """Starting against a nonexistent path raises InvalidWatchTargetError."""
        missing = tmp_path / "does-not-exist"
        watcher = WatchdogFileWatcher(paths=[missing])
        with pytest.raises(InvalidWatchTargetError, match="does not exist"):
            await watcher.start()
        assert watcher.is_running is False

    async def test_file_instead_of_directory_raises(self, tmp_path: Path) -> None:
        """Starting against a file (not a directory) raises InvalidWatchTargetError."""
        a_file = tmp_path / "file.txt"
        a_file.write_text("content")
        watcher = WatchdogFileWatcher(paths=[a_file])
        with pytest.raises(InvalidWatchTargetError, match="is not a directory"):
            await watcher.start()

    async def test_one_invalid_path_among_valid_ones_still_raises(self, tmp_path: Path) -> None:
        """Validation checks every path, not just the first one."""
        valid_dir = tmp_path / "valid"
        valid_dir.mkdir()
        missing_dir = tmp_path / "missing"
        watcher = WatchdogFileWatcher(paths=[valid_dir, missing_dir])
        with pytest.raises(InvalidWatchTargetError):
            await watcher.start()


class TestStartStopLifecycle:
    """Tests for the start/stop state machine."""

    async def test_double_start_raises(self, tmp_path: Path) -> None:
        """Starting an already-running watcher raises WatcherAlreadyRunningError."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        await watcher.start()
        try:
            with pytest.raises(WatcherAlreadyRunningError):
                await watcher.start()
        finally:
            await watcher.stop()

    async def test_stop_without_start_is_a_safe_noop(self, tmp_path: Path) -> None:
        """Stopping a watcher that was never started does nothing and doesn't raise."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        await watcher.stop()
        assert watcher.is_running is False

    async def test_stop_is_idempotent(self, tmp_path: Path) -> None:
        """Calling stop() twice in a row is safe."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        await watcher.start()
        await watcher.stop()
        await watcher.stop()
        assert watcher.is_running is False

    async def test_is_running_reflects_state(self, tmp_path: Path) -> None:
        """`is_running` toggles True after start() and False after stop()."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        assert watcher.is_running is False
        await watcher.start()
        assert watcher.is_running is True
        await watcher.stop()
        assert watcher.is_running is False

    async def test_restart_after_stop_is_allowed(self, tmp_path: Path) -> None:
        """A watcher can be started again after being cleanly stopped."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        await watcher.start()
        await watcher.stop()
        await watcher.start()
        assert watcher.is_running is True
        await watcher.stop()


class TestSubscription:
    """Tests for observer registration bookkeeping."""

    def test_subscribing_a_non_observer_raises_type_error(self, tmp_path: Path) -> None:
        """An object without on_file_event fails fast at subscribe() time."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        with pytest.raises(TypeError, match="does not implement FileSystemEventObserver"):
            watcher.subscribe(object())  # type: ignore[arg-type]

    def test_subscribe_is_idempotent(self, tmp_path: Path) -> None:
        """Subscribing the same observer twice does not duplicate it."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        observer = CollectingObserver()
        watcher.subscribe(observer)
        watcher.subscribe(observer)
        # No public accessor for the raw list; verify indirectly via unsubscribe.
        watcher.unsubscribe(observer)
        # A second unsubscribe of an already-removed observer must be a no-op.
        watcher.unsubscribe(observer)

    def test_unsubscribe_unknown_observer_is_a_noop(self, tmp_path: Path) -> None:
        """Unsubscribing an observer that was never registered doesn't raise."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        observer = CollectingObserver()
        watcher.unsubscribe(observer)


class TestTranslatedEventDispatchGuards:
    """Tests for internal dispatch guarding against a torn-down loop."""

    def test_dispatch_before_start_is_a_noop(self, tmp_path: Path) -> None:
        """Dispatching before `start()` has captured a loop does nothing."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        event = FileSystemEvent(
            event_type=FileSystemEventType.CREATED,
            src_path=tmp_path / "f.txt",
            is_directory=False,
        )
        # Must not raise even though no event loop has been captured yet.
        watcher._on_translated_event(event)  # noqa: SLF001 - white-box lifecycle test


class TestStartFailureHandling:
    """Tests for `start()` wrapping low-level failures as `FileWatcherError`."""

    async def test_underlying_observer_start_failure_raises_file_watcher_error(
        self, tmp_path: Path
    ) -> None:
        """An `OSError` from the real observer's `start()` becomes a `FileWatcherError`."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        with patch(
            "securesync.infrastructure.filesystem.watchdog_watcher.WatchdogObserver"
        ) as mock_observer_cls:
            mock_observer_cls.return_value.start.side_effect = OSError(
                "inotify watch limit reached"
            )
            with pytest.raises(FileWatcherError, match="Failed to start filesystem watcher"):
                await watcher.start()

        # The failure must not leave the watcher in a "started" state.
        assert watcher.is_running is False


class TestStopFailureHandling:
    """Tests for `stop()`'s error and timeout branches against a real observer."""

    async def test_join_failure_raises_file_watcher_error(self, tmp_path: Path) -> None:
        """An exception from the observer thread's `join()` becomes a `FileWatcherError`."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        await watcher.start()
        observer = watcher._watchdog_observer  # noqa: SLF001 - white-box lifecycle test
        assert observer is not None

        with (
            patch.object(observer, "join", side_effect=RuntimeError("join failed")),
            pytest.raises(FileWatcherError, match="Failed to stop filesystem watcher"),
        ):
            await watcher.stop()

        # Clean up the real background thread now that `join` is unpatched.
        observer.join(timeout=2.0)

    async def test_warns_when_thread_is_still_alive_after_join(self, tmp_path: Path) -> None:
        """If the background thread outlives `join()`, `stop()` warns but doesn't raise."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        await watcher.start()
        observer = watcher._watchdog_observer  # noqa: SLF001 - white-box lifecycle test
        assert observer is not None

        with patch.object(observer, "is_alive", return_value=True):
            await watcher.stop()  # must not raise despite is_alive() reporting True

        assert watcher.is_running is False


class TestDispatchFutureExceptionLogging:
    """White-box tests for `_log_dispatch_future_exception`."""

    def test_logs_when_the_future_failed(self, tmp_path: Path) -> None:
        """An exception on the future is logged via structlog at ERROR."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        future: Future[None] = Future()
        future.set_exception(RuntimeError("dispatch machinery blew up"))

        with structlog.testing.capture_logs() as captured:
            watcher._log_dispatch_future_exception(future)  # noqa: SLF001

        assert len(captured) == 1
        assert captured[0]["event"] == "event_notification_future_failed"
        assert captured[0]["log_level"] == "error"

    def test_does_nothing_when_the_future_succeeded(self, tmp_path: Path) -> None:
        """A successful future produces no log output."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        future: Future[None] = Future()
        future.set_result(None)

        with structlog.testing.capture_logs() as captured:
            watcher._log_dispatch_future_exception(future)  # noqa: SLF001

        assert captured == []

    def test_does_nothing_when_the_future_was_cancelled(self, tmp_path: Path) -> None:
        """A cancelled future produces no log output (and doesn't raise)."""
        watcher = WatchdogFileWatcher(paths=[tmp_path])
        future: Future[None] = Future()
        future.cancel()

        with structlog.testing.capture_logs() as captured:
            watcher._log_dispatch_future_exception(future)  # noqa: SLF001

        assert captured == []

    """White-box tests for `_DispatchingEventHandler`'s exception isolation."""

    def test_callback_exception_does_not_propagate(self, tmp_path: Path) -> None:
        """A raising `on_translated_event` callback is caught and logged, not re-raised."""
        from watchdog.events import FileCreatedEvent

        def _raising_callback(event: FileSystemEvent) -> None:
            raise RuntimeError("simulated callback bug")

        handler = _DispatchingEventHandler(
            debouncer=EventDebouncer(window_seconds=0.0),
            on_translated_event=_raising_callback,
        )

        raw_event = FileCreatedEvent(str(tmp_path / "f.txt"))
        # Must not raise - a bug in the callback must never kill the
        # watchdog background thread.
        handler.on_any_event(raw_event)

    def test_ignorable_raw_event_is_dropped_quietly(self, tmp_path: Path) -> None:
        """A known-but-out-of-scope event type (e.g. `closed`) is dropped, logged at DEBUG."""
        calls: list[FileSystemEvent] = []

        handler = _DispatchingEventHandler(
            debouncer=EventDebouncer(window_seconds=0.0),
            on_translated_event=calls.append,
        )

        class _ClosedRawEvent:
            event_type = "closed"
            src_path = str(tmp_path / "f.txt")
            dest_path = ""
            is_directory = False

        with structlog.testing.capture_logs() as captured:
            handler.on_any_event(_ClosedRawEvent())  # type: ignore[arg-type]

        assert calls == []
        assert captured == [
            {"raw_type": "closed", "event": "ignored_watchdog_event", "log_level": "debug"}
        ]

    def test_genuinely_unrecognized_raw_event_is_dropped_loudly(self, tmp_path: Path) -> None:
        """A truly unrecognized event type is dropped, logged at WARNING (not DEBUG)."""
        calls: list[FileSystemEvent] = []

        handler = _DispatchingEventHandler(
            debouncer=EventDebouncer(window_seconds=0.0),
            on_translated_event=calls.append,
        )

        class _BogusRawEvent:
            event_type = "some_future_watchdog_event_type"
            src_path = str(tmp_path / "f.txt")
            dest_path = ""
            is_directory = False

        with structlog.testing.capture_logs() as captured:
            handler.on_any_event(_BogusRawEvent())  # type: ignore[arg-type]

        assert calls == []
        assert captured == [
            {
                "raw_type": "some_future_watchdog_event_type",
                "event": "unrecognized_watchdog_event",
                "log_level": "warning",
            }
        ]
