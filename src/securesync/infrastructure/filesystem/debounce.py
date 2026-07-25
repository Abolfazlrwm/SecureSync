"""Debouncing for duplicate filesystem events.

Many OS-level filesystem-notification backends emit multiple raw events
for what is logically a single change (for example, several MODIFIED
notifications for one buffered write, or a CREATED immediately followed
by a MODIFIED for the same new file). This is a technical characteristic
of the underlying notification mechanism, not a business rule, so it is
handled entirely within the infrastructure layer.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Hashable


class EventDebouncer:
    """Thread-safe filter that suppresses duplicate events within a window.

    An event is identified by an opaque, hashable key (typically
    ``FileSystemEvent.dedup_key``). The first occurrence of a key is
    always allowed through; any repeat of the same key within
    ``window_seconds`` of the first occurrence is suppressed.

    Entries older than ``window_seconds`` are evicted opportunistically
    on every call (they can no longer suppress anything, so keeping them
    around would only leak memory). For a long-running watcher this
    bounds memory to keys seen within the last ``window_seconds``, not
    the full lifetime of the process.

    Safe to call concurrently from multiple threads, since a single
    :class:`EventDebouncer` instance is shared between the ``watchdog``
    background thread(s) and, potentially, other callers.
    """

    def __init__(self, window_seconds: float = 0.5) -> None:
        """Initialize the debouncer.

        Args:
            window_seconds: Minimum time, in seconds, that must elapse
                before an identical key is allowed through again. Must be
                ``>= 0``; ``0`` disables debouncing (every event passes).

        Raises:
            ValueError: If ``window_seconds`` is negative.
        """
        if window_seconds < 0:
            raise ValueError("window_seconds must be >= 0")
        self._window_seconds = window_seconds
        # Insertion/update order == recency order (see `should_emit`),
        # which lets `_evict_stale` prune from the front in O(evicted).
        self._last_seen: OrderedDict[Hashable, float] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def window_seconds(self) -> float:
        """The configured debounce window, in seconds."""
        return self._window_seconds

    def should_emit(self, key: Hashable) -> bool:
        """Decide whether an event with this key should be emitted.

        Args:
            key: A hashable identifier for the logical event (typically
                event type + path).

        Returns:
            ``True`` if this is the first occurrence of ``key`` within
            the debounce window and it should be dispatched; ``False``
            if it's a duplicate that should be suppressed.
        """
        if self._window_seconds == 0:
            return True

        now = time.monotonic()
        with self._lock:
            self._evict_stale(now)

            last = self._last_seen.get(key)
            if last is not None and (now - last) < self._window_seconds:
                return False
            # Re-inserting (or moving) `key` to the end keeps the dict in
            # recency order, which `_evict_stale` relies on.
            self._last_seen[key] = now
            self._last_seen.move_to_end(key)
            return True

    def _evict_stale(self, now: float) -> None:
        """Drop entries too old to suppress anything, freeing memory.

        Must be called with `_lock` already held.

        Args:
            now: The current `time.monotonic()` reading.
        """
        while self._last_seen:
            oldest_key = next(iter(self._last_seen))
            if now - self._last_seen[oldest_key] < self._window_seconds:
                break
            del self._last_seen[oldest_key]

    def reset(self) -> None:
        """Clear all recorded event timestamps."""
        with self._lock:
            self._last_seen.clear()
