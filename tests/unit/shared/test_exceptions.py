"""Unit tests for `securesync.shared.exceptions`."""

from __future__ import annotations

from securesync.shared.exceptions import FileWatcherError, SecureSyncError


def test_file_watcher_error_derives_from_secure_sync_error() -> None:
    """`FileWatcherError` is catchable as the shared base error."""
    assert issubclass(FileWatcherError, SecureSyncError)


def test_secure_sync_error_derives_from_exception() -> None:
    """`SecureSyncError` is a plain `Exception`."""
    assert issubclass(SecureSyncError, Exception)


def test_file_watcher_error_carries_message_and_cause() -> None:
    """Chaining preserves the original cause via `__cause__`."""
    cause = OSError("inotify limit reached")
    try:
        try:
            raise cause
        except OSError as exc:
            raise FileWatcherError("Failed to start filesystem watcher") from exc
    except FileWatcherError as error:
        assert str(error) == "Failed to start filesystem watcher"
        assert error.__cause__ is cause
