"""Test doubles shared across the test suite.

Per CONTRIBUTING.md, every port added to ``domain/`` needs at least one
fake adapter in ``tests/`` so application-layer code can be exercised
without any real I/O. ``FakeFileWatcher`` is that fake for
``domain.watcher.FileWatcher``; ``CollectingObserver`` and
``FailingObserver`` are test doubles for
``domain.watcher.FileSystemEventObserver``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from securesync.domain.events import FileSystemEvent
from securesync.domain.watcher import FileSystemEventObserver, FileWatcher


class FakeFileWatcher(FileWatcher):
    """In-memory fake ``FileWatcher`` for testing application-layer code.

    Records every call made to it and lets a test optionally force
    ``start``/``stop`` to raise, without touching a real filesystem or
    thread.
    """

    def __init__(self) -> None:
        """Initialize the fake with no observers and a stopped state."""
        self.start_calls = 0
        self.stop_calls = 0
        self._observers: list[FileSystemEventObserver] = []
        self._running = False
        self.raise_on_start: Exception | None = None
        self.raise_on_stop: Exception | None = None

    async def start(self) -> None:
        """Record the call and flip to running, unless configured to fail."""
        self.start_calls += 1
        if self.raise_on_start is not None:
            raise self.raise_on_start
        self._running = True

    async def stop(self) -> None:
        """Record the call and flip to stopped, unless configured to fail."""
        self.stop_calls += 1
        if self.raise_on_stop is not None:
            raise self.raise_on_stop
        self._running = False

    def subscribe(self, observer: FileSystemEventObserver) -> None:
        """Register ``observer``, mirroring the real port's contract."""
        if observer not in self._observers:
            self._observers.append(observer)

    def unsubscribe(self, observer: FileSystemEventObserver) -> None:
        """Remove ``observer``, mirroring the real port's contract."""
        if observer in self._observers:
            self._observers.remove(observer)

    @property
    def is_running(self) -> bool:
        """Whether ``start`` has been called without a matching ``stop``."""
        return self._running

    @property
    def observers(self) -> list[FileSystemEventObserver]:
        """A snapshot of currently-subscribed observers."""
        return list(self._observers)

    async def emit(self, event: FileSystemEvent) -> None:
        """Test helper: notify every subscribed observer of ``event``.

        Args:
            event: The event to deliver to all subscribed observers.
        """
        for observer in list(self._observers):
            await observer.on_file_event(event)


class CollectingObserver:
    """Observer test double that records every event it receives."""

    def __init__(self) -> None:
        """Initialize with an empty event log."""
        self.events: list[FileSystemEvent] = []
        self._queue: asyncio.Queue[FileSystemEvent] = asyncio.Queue()

    async def on_file_event(self, event: FileSystemEvent) -> None:
        """Append ``event`` to the log and wake any waiter.

        Args:
            event: The event delivered by the watcher.
        """
        self.events.append(event)
        await self._queue.put(event)

    async def wait_for(self, count: int, timeout_seconds: float = 5.0) -> list[FileSystemEvent]:
        """Block until at least ``count`` events have been collected.

        A single real filesystem operation often produces more than one
        raw notification (e.g. a file write also touches the parent
        directory's mtime), so prefer :meth:`wait_until` with a specific
        predicate when a test cares about *which* events arrived, not
        just how many.

        Args:
            count: The number of events to wait for.
            timeout_seconds: Maximum time, in seconds, to wait.

        Returns:
            A snapshot of the collected events once ``count`` is reached.

        Raises:
            TimeoutError: If ``count`` events aren't collected in time.
        """
        return await self.wait_until(
            lambda events: len(events) >= count, timeout_seconds=timeout_seconds
        )

    async def wait_until(
        self,
        predicate: Callable[[list[FileSystemEvent]], bool],
        timeout_seconds: float = 5.0,
    ) -> list[FileSystemEvent]:
        """Block until the collected events satisfy ``predicate``.

        Args:
            predicate: Called with a snapshot of collected events after
                every new arrival; should return ``True`` once the
                awaited condition is met.
            timeout_seconds: Maximum time, in seconds, to wait.

        Returns:
            A snapshot of the collected events once ``predicate`` holds.

        Raises:
            TimeoutError: If the predicate never becomes true in time.
        """

        async def _wait_until_true() -> None:
            while not predicate(self.events):
                await self._queue.get()

        await asyncio.wait_for(_wait_until_true(), timeout=timeout_seconds)
        return list(self.events)


class FailingObserver:
    """Observer test double that always raises, to test error isolation."""

    def __init__(self) -> None:
        """Initialize with a zeroed call counter."""
        self.call_count = 0

    async def on_file_event(self, event: FileSystemEvent) -> None:
        """Increment the call counter, then always raise.

        Args:
            event: The event delivered by the watcher (unused).

        Raises:
            RuntimeError: Always, to simulate a buggy observer.
        """
        self.call_count += 1
        raise RuntimeError("simulated observer failure")
