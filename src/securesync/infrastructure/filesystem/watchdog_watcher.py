"""``watchdog``-based adapter for the ``FileWatcher`` domain port.

This is the only module in the codebase that imports ``watchdog``
directly. Everything above the infrastructure layer (application,
domain) depends solely on ``securesync.domain.watcher.FileWatcher``.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Iterable
from concurrent.futures import Future
from pathlib import Path

import structlog
from watchdog.events import FileSystemEvent as WatchdogRawEvent
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer as WatchdogObserver
from watchdog.observers.api import BaseObserver as WatchdogBaseObserver

from securesync.domain.events import FileSystemEvent
from securesync.domain.exceptions import InvalidWatchTargetError, WatcherAlreadyRunningError
from securesync.domain.watcher import FileSystemEventObserver, FileWatcher
from securesync.infrastructure.filesystem.debounce import EventDebouncer
from securesync.infrastructure.filesystem.event_translator import is_ignorable_event_type, translate
from securesync.shared.exceptions import FileWatcherError

logger = structlog.get_logger(__name__)

_DEFAULT_DEBOUNCE_SECONDS = 0.5
_DEFAULT_SHUTDOWN_TIMEOUT = 5.0


class _DispatchingEventHandler(FileSystemEventHandler):
    """Internal ``watchdog`` handler that translates and forwards events.

    Runs entirely on ``watchdog``'s background OS thread and never
    touches ``asyncio`` directly. Translated, debounced events are handed
    to ``on_translated_event``, which is responsible for thread-safe
    dispatch onto the asyncio event loop.
    """

    def __init__(
        self,
        debouncer: EventDebouncer,
        on_translated_event: Callable[[FileSystemEvent], None],
    ) -> None:
        """Initialize the handler.

        Args:
            debouncer: Shared debouncer used to suppress duplicate events.
            on_translated_event: Callback invoked with each translated,
                non-debounced event.
        """
        super().__init__()
        self._debouncer = debouncer
        self._on_translated_event = on_translated_event

    def on_any_event(self, event: WatchdogRawEvent) -> None:
        """Translate, debounce, and forward every raw ``watchdog`` event.

        Args:
            event: The raw event dispatched by ``watchdog``.
        """
        try:
            domain_event = translate(event)
        except ValueError:
            if is_ignorable_event_type(event.event_type):
                # Routine noise (e.g. open/close notifications) - expected
                # on every read/write, not worth a WARNING in production.
                logger.debug("ignored_watchdog_event", raw_type=event.event_type)
            else:
                logger.warning("unrecognized_watchdog_event", raw_type=event.event_type)
            return

        if not self._debouncer.should_emit(domain_event.dedup_key):
            logger.debug(
                "event_debounced",
                event_type=domain_event.event_type.value,
                path=str(domain_event.src_path),
            )
            return

        try:
            self._on_translated_event(domain_event)
        except Exception:  # noqa: BLE001 - a handler bug must not kill the watcher thread
            logger.exception("event_dispatch_failed", path=str(domain_event.src_path))


class WatchdogFileWatcher(FileWatcher):
    """``watchdog``-based implementation of the ``FileWatcher`` port.

    Monitors one or more directories, optionally recursively, and
    notifies registered observers asynchronously of every
    create/modify/delete/move event. Duplicate rapid-fire notifications
    for the same logical change are suppressed via debouncing.
    """

    def __init__(
        self,
        paths: Iterable[Path],
        *,
        recursive: bool = True,
        debounce_seconds: float = _DEFAULT_DEBOUNCE_SECONDS,
        shutdown_timeout: float = _DEFAULT_SHUTDOWN_TIMEOUT,
    ) -> None:
        """Initialize the watcher.

        Args:
            paths: One or more directories to monitor.
            recursive: Whether to monitor subdirectories as well.
            debounce_seconds: Debounce window; see :class:`EventDebouncer`.
            shutdown_timeout: Max seconds to wait for the background
                watcher thread to stop during :meth:`stop`.

        Raises:
            ValueError: If ``paths`` is empty.
        """
        # De-duplicate literal repeats (e.g. the caller passing the same
        # directory twice); scheduling the same path with `watchdog` more
        # than once would double-emit every event from it. This does not
        # attempt to detect *overlapping* paths (e.g. a parent and its own
        # child both listed) - resolving that would mean silently
        # rewriting what the caller asked to watch, which is a bigger
        # decision than a duplicate-literal safety net.
        self._paths: tuple[Path, ...] = tuple(dict.fromkeys(paths))
        if not self._paths:
            raise ValueError("At least one path must be provided")

        self._recursive = recursive
        self._debouncer = EventDebouncer(debounce_seconds)
        self._shutdown_timeout = shutdown_timeout

        self._observers: list[FileSystemEventObserver] = []
        self._observers_lock = threading.Lock()

        self._watchdog_observer: WatchdogBaseObserver | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._running = False
        self._state_lock = asyncio.Lock()

    def subscribe(self, observer: FileSystemEventObserver) -> None:
        """See :meth:`FileWatcher.subscribe`.

        Raises:
            TypeError: If ``observer`` doesn't implement
                :class:`FileSystemEventObserver` (has no ``on_file_event``
                method). Without this check, a caller mistake here would
                otherwise fail silently on every single event forever,
                since dispatch failures are caught and only logged (see
                :meth:`_notify_observers`) rather than raised.
        """
        if not isinstance(observer, FileSystemEventObserver):
            raise TypeError(
                f"{type(observer).__name__} does not implement FileSystemEventObserver "
                "(missing an async on_file_event(event) method)"
            )
        with self._observers_lock:
            if observer not in self._observers:
                self._observers.append(observer)

    def unsubscribe(self, observer: FileSystemEventObserver) -> None:
        """See :meth:`FileWatcher.unsubscribe`."""
        with self._observers_lock:
            if observer in self._observers:
                self._observers.remove(observer)

    @property
    def is_running(self) -> bool:
        """See :attr:`FileWatcher.is_running`."""
        return self._running

    async def start(self) -> None:
        """See :meth:`FileWatcher.start`."""
        async with self._state_lock:
            if self._running:
                raise WatcherAlreadyRunningError("Watcher is already running")

            self._validate_paths()

            self._loop = asyncio.get_running_loop()
            handler = _DispatchingEventHandler(self._debouncer, self._on_translated_event)
            watchdog_observer = WatchdogObserver()
            try:
                for path in self._paths:
                    watchdog_observer.schedule(handler, str(path), recursive=self._recursive)
                watchdog_observer.start()
            except OSError as exc:
                raise FileWatcherError(f"Failed to start filesystem watcher: {exc}") from exc

            self._watchdog_observer = watchdog_observer
            self._running = True

        logger.info(
            "filesystem_watcher_started",
            paths=[str(p) for p in self._paths],
            recursive=self._recursive,
        )

    async def stop(self) -> None:
        """See :meth:`FileWatcher.stop`."""
        async with self._state_lock:
            if not self._running or self._watchdog_observer is None:
                logger.debug("filesystem_watcher_stop_noop")
                return

            watchdog_observer = self._watchdog_observer
            self._running = False
            self._watchdog_observer = None
            self._loop = None

        watchdog_observer.stop()
        try:
            await asyncio.to_thread(watchdog_observer.join, self._shutdown_timeout)
        except Exception as exc:  # noqa: BLE001
            logger.exception("filesystem_watcher_stop_failed")
            raise FileWatcherError("Failed to stop filesystem watcher cleanly") from exc

        if watchdog_observer.is_alive():
            logger.warning("filesystem_watcher_stop_timeout", timeout=self._shutdown_timeout)
        else:
            logger.info("filesystem_watcher_stopped")

    def _validate_paths(self) -> None:
        """Ensure every configured path exists and is a directory.

        Raises:
            InvalidWatchTargetError: If any configured path is missing or
                isn't a directory.
        """
        for path in self._paths:
            if not path.exists():
                raise InvalidWatchTargetError(f"Watch target does not exist: {path}")
            if not path.is_dir():
                raise InvalidWatchTargetError(f"Watch target is not a directory: {path}")

    def _on_translated_event(self, event: FileSystemEvent) -> None:
        """Schedule thread-safe async dispatch of a translated event.

        Called synchronously from ``watchdog``'s background thread.

        Args:
            event: The translated, debounced domain event to dispatch.
        """
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        future = asyncio.run_coroutine_threadsafe(self._notify_observers(event), loop)
        future.add_done_callback(self._log_dispatch_future_exception)

    def _log_dispatch_future_exception(self, future: Future[None]) -> None:
        """Log any exception that escaped `_notify_observers` itself.

        Per-observer failures are already caught and logged inside
        `_notify_observers`; this only catches something going wrong in
        the dispatch machinery around that loop (otherwise silently
        dropped, since nothing else ever calls `future.result()`).

        Args:
            future: The completed future for one `_notify_observers` call.
        """
        if future.cancelled():
            return
        exc = future.exception()
        if exc is not None:
            logger.error("event_notification_future_failed", exc_info=exc)

    async def _notify_observers(self, event: FileSystemEvent) -> None:
        """Notify every currently-subscribed observer of one event.

        Args:
            event: The event to dispatch.
        """
        with self._observers_lock:
            observers = list(self._observers)

        for observer in observers:
            try:
                await observer.on_file_event(event)
            except Exception:  # noqa: BLE001 - one observer's bug must not break others
                logger.exception(
                    "observer_notification_failed",
                    observer=type(observer).__name__,
                )
