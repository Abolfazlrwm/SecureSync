"""Ports (interfaces) for filesystem monitoring.

This module defines the boundary between the domain and any concrete
filesystem-notification technology. It contains two cooperating
abstractions that together implement the Observer pattern:

- :class:`FileWatcher` is the *subject*: a port that infrastructure
  adapters implement (e.g. a ``watchdog``-based adapter).
- :class:`FileSystemEventObserver` is the *observer*: anything that wants
  to be notified of filesystem changes implements this protocol and
  registers itself with a :class:`FileWatcher` via ``subscribe``.

Application code depends only on these abstractions, never on a concrete
adapter — the concrete adapter is wired in at the composition root via
dependency injection.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from securesync.domain.events import FileSystemEvent


@runtime_checkable
class FileSystemEventObserver(Protocol):
    """Observer pattern participant that reacts to filesystem events.

    Any consumer that wants to be notified of filesystem changes (a
    future chunk engine, a metadata indexer, a logger) implements this
    protocol and registers with a :class:`FileWatcher` via ``subscribe``.
    Implementations decide *what to do* with an event; the watcher itself
    never does.
    """

    async def on_file_event(self, event: FileSystemEvent) -> None:
        """Handle a single filesystem event.

        Args:
            event: The filesystem event that occurred.
        """
        ...


class FileWatcher(ABC):
    """Port for monitoring filesystem changes across one or more directories.

    Concrete adapters (infrastructure layer) implement this interface
    using a real filesystem-notification mechanism. The watcher only
    detects and dispatches events to subscribed observers; it never
    decides what to do about them — that decision belongs to whatever
    observer is registered.
    """

    @abstractmethod
    async def start(self) -> None:
        """Begin monitoring and dispatching events to subscribed observers.

        Raises:
            WatcherAlreadyRunningError: If the watcher is already running.
            InvalidWatchTargetError: If a configured path doesn't exist or
                isn't a directory.
        """
        raise NotImplementedError

    @abstractmethod
    async def stop(self) -> None:
        """Stop monitoring and release underlying resources.

        Must be safe to call even if the watcher was never started, and
        idempotent if called multiple times in a row.
        """
        raise NotImplementedError

    @abstractmethod
    def subscribe(self, observer: FileSystemEventObserver) -> None:
        """Register an observer to receive future filesystem events.

        Args:
            observer: The observer to register. Registering the same
                observer twice has no additional effect.

        Raises:
            TypeError: Implementations may (but aren't required to)
                validate that ``observer`` actually implements
                :class:`FileSystemEventObserver` and reject it early
                rather than silently failing on every future event.
        """
        raise NotImplementedError

    @abstractmethod
    def unsubscribe(self, observer: FileSystemEventObserver) -> None:
        """Remove a previously-registered observer.

        Args:
            observer: The observer to remove. A no-op if the observer
                isn't currently registered.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """Whether the watcher is currently monitoring."""
        raise NotImplementedError
