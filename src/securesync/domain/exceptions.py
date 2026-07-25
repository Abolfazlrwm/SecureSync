"""Domain-level exceptions for filesystem monitoring.

These exceptions describe failures in terms the domain understands
(an invalid watch target, an invalid state transition) without any
knowledge of the concrete technology (``watchdog``, the OS notification
API, etc.) that ultimately raised them. Infrastructure adapters are
responsible for translating low-level failures into these types.
"""

from __future__ import annotations


class WatcherError(Exception):
    """Base class for all filesystem-watcher domain errors."""


class WatcherAlreadyRunningError(WatcherError):
    """Raised when ``start()`` is called on an already-running watcher."""


class InvalidWatchTargetError(WatcherError):
    """Raised when a configured watch path is missing or not a directory."""
