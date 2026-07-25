"""Use case: monitor one or more directories for filesystem changes."""

from __future__ import annotations

from types import TracebackType

import structlog

from securesync.domain.watcher import FileSystemEventObserver, FileWatcher

logger = structlog.get_logger(__name__)


class MonitorDirectoriesUseCase:
    """Orchestrates filesystem monitoring against the ``FileWatcher`` port.

    This use case owns the lifecycle (start/stop) of an injected
    ``FileWatcher`` and the observers notified of every event it detects.
    It contains no filesystem-specific logic of its own — that belongs to
    the concrete ``FileWatcher`` adapter supplied by the caller (the
    composition root), in keeping with Dependency Inversion.
    """

    def __init__(self, watcher: FileWatcher) -> None:
        """Initialize the use case.

        Args:
            watcher: A concrete ``FileWatcher`` adapter, injected by the
                composition root.
        """
        self._watcher = watcher

    def register_observer(self, observer: FileSystemEventObserver) -> None:
        """Register an observer to be notified of every filesystem event.

        Args:
            observer: The observer to register.
        """
        self._watcher.subscribe(observer)
        logger.debug("observer_registered", observer=type(observer).__name__)

    def unregister_observer(self, observer: FileSystemEventObserver) -> None:
        """Remove a previously registered observer.

        Args:
            observer: The observer to remove.
        """
        self._watcher.unsubscribe(observer)
        logger.debug("observer_unregistered", observer=type(observer).__name__)

    async def start(self) -> None:
        """Start monitoring.

        Raises:
            WatcherAlreadyRunningError: If monitoring is already active.
            InvalidWatchTargetError: If a configured directory doesn't
                exist or isn't a directory.
        """
        logger.info("monitoring_starting")
        await self._watcher.start()
        logger.info("monitoring_started")

    async def stop(self) -> None:
        """Gracefully stop monitoring, releasing all underlying resources.

        Safe to call even if monitoring was never started.
        """
        logger.info("monitoring_stopping")
        await self._watcher.stop()
        logger.info("monitoring_stopped")

    @property
    def is_running(self) -> bool:
        """Whether monitoring is currently active."""
        return self._watcher.is_running

    async def __aenter__(self) -> MonitorDirectoriesUseCase:
        """Start monitoring on entering an ``async with`` block.

        Returns:
            This use case instance, already monitoring.
        """
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Guarantee graceful shutdown on leaving an ``async with`` block."""
        await self.stop()
