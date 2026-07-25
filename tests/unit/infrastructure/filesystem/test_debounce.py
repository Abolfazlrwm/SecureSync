"""Unit tests for `securesync.infrastructure.filesystem.debounce`."""

from __future__ import annotations

import threading
import time

import pytest

from securesync.infrastructure.filesystem.debounce import EventDebouncer


class TestEventDebouncerConstruction:
    """Tests for constructing `EventDebouncer`."""

    def test_negative_window_raises(self) -> None:
        """A negative debounce window is rejected."""
        with pytest.raises(ValueError, match="window_seconds must be >= 0"):
            EventDebouncer(window_seconds=-0.1)

    def test_window_seconds_is_exposed(self) -> None:
        """The configured window is readable back."""
        debouncer = EventDebouncer(window_seconds=1.5)
        assert debouncer.window_seconds == 1.5


class TestShouldEmit:
    """Tests for `EventDebouncer.should_emit`."""

    def test_first_occurrence_is_always_emitted(self) -> None:
        """The very first time a key is seen, it's always allowed through."""
        debouncer = EventDebouncer(window_seconds=1.0)
        assert debouncer.should_emit("key-a") is True

    def test_duplicate_within_window_is_suppressed(self) -> None:
        """A repeat of the same key inside the window is suppressed."""
        debouncer = EventDebouncer(window_seconds=1.0)
        assert debouncer.should_emit("key-a") is True
        assert debouncer.should_emit("key-a") is False

    def test_duplicate_after_window_is_emitted_again(self) -> None:
        """Once the window elapses, the same key is allowed through again."""
        debouncer = EventDebouncer(window_seconds=0.05)
        assert debouncer.should_emit("key-a") is True
        time.sleep(0.08)
        assert debouncer.should_emit("key-a") is True

    def test_different_keys_are_independent(self) -> None:
        """Debouncing one key never suppresses a different key."""
        debouncer = EventDebouncer(window_seconds=1.0)
        assert debouncer.should_emit("key-a") is True
        assert debouncer.should_emit("key-b") is True

    def test_zero_window_disables_debouncing(self) -> None:
        """A window of 0 lets every event through, including repeats."""
        debouncer = EventDebouncer(window_seconds=0)
        assert debouncer.should_emit("key-a") is True
        assert debouncer.should_emit("key-a") is True
        assert debouncer.should_emit("key-a") is True

    def test_reset_clears_history(self) -> None:
        """`reset` forgets prior occurrences, so the next call is a first."""
        debouncer = EventDebouncer(window_seconds=10.0)
        assert debouncer.should_emit("key-a") is True
        assert debouncer.should_emit("key-a") is False
        debouncer.reset()
        assert debouncer.should_emit("key-a") is True


class TestBoundedMemory:
    """Tests proving stale entries are evicted rather than retained forever.

    A debouncer that never forgets old keys would leak memory in a
    long-running watcher monitoring a directory with high churn (many
    distinct paths created and deleted over days/weeks). Entries older
    than the debounce window can never suppress anything, so they must
    not be retained.
    """

    def test_stale_entries_are_evicted_after_the_window_elapses(self) -> None:
        """Once a key's entry is older than the window, it's dropped internally."""
        debouncer = EventDebouncer(window_seconds=0.05)
        debouncer.should_emit("key-a")
        assert len(debouncer._last_seen) == 1  # noqa: SLF001 - white-box memory test

        time.sleep(0.08)
        # A call for an unrelated key triggers opportunistic eviction of
        # the now-stale "key-a" entry.
        debouncer.should_emit("key-b")

        assert "key-a" not in debouncer._last_seen  # noqa: SLF001
        assert len(debouncer._last_seen) == 1  # only "key-b" remains

    def test_memory_stays_bounded_under_sustained_high_churn(self) -> None:
        """Many distinct keys over time never accumulate past the recent window."""
        debouncer = EventDebouncer(window_seconds=0.02)
        for i in range(500):
            debouncer.should_emit(f"key-{i}")
            if i % 50 == 0:
                # Let the window lapse periodically, simulating churn
                # spread out over real time rather than a tight burst.
                time.sleep(0.03)

        # However many keys were emitted, only the ones seen within the
        # last window_seconds should still be tracked - nowhere near 500.
        assert len(debouncer._last_seen) < 50  # noqa: SLF001 - white-box memory test


class TestThreadSafety:
    """Tests confirming `EventDebouncer` tolerates concurrent access."""

    def test_concurrent_calls_do_not_corrupt_state(self) -> None:
        """Many threads hammering the same key never raises or deadlocks."""
        debouncer = EventDebouncer(window_seconds=0.01)
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                for i in range(200):
                    debouncer.should_emit(f"key-{i % 5}")
            except BaseException as exc:  # noqa: BLE001 - capture for the assertion below
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5.0)

        assert not errors
        assert all(not thread.is_alive() for thread in threads)
