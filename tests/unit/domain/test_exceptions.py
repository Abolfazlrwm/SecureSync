"""Unit tests for `securesync.domain.exceptions`."""

from __future__ import annotations

import pytest

from securesync.domain.exceptions import (
    InvalidWatchTargetError,
    WatcherAlreadyRunningError,
    WatcherError,
)


@pytest.mark.parametrize(
    "exc_class",
    [WatcherAlreadyRunningError, InvalidWatchTargetError],
)
def test_all_watcher_errors_derive_from_watcher_error(
    exc_class: type[WatcherError],
) -> None:
    """Every specific watcher exception is also a `WatcherError`."""
    assert issubclass(exc_class, WatcherError)


def test_watcher_error_derives_from_exception() -> None:
    """`WatcherError` itself is a plain `Exception`, not tied to any framework."""
    assert issubclass(WatcherError, Exception)


def test_exception_messages_are_preserved() -> None:
    """Constructing with a message preserves it via `str()`."""
    error = InvalidWatchTargetError("Watch target does not exist: /nope")
    assert str(error) == "Watch target does not exist: /nope"
