"""Unit tests for `securesync.shared.exceptions`."""

from __future__ import annotations

from securesync.shared.exceptions import ChunkEngineError, FileWatcherError, SecureSyncError


def test_file_watcher_error_derives_from_secure_sync_error() -> None:
    """`FileWatcherError` is catchable as the shared base error."""
    assert issubclass(FileWatcherError, SecureSyncError)


def test_chunk_engine_error_derives_from_secure_sync_error() -> None:
    """`ChunkEngineError` is catchable as the shared base error."""
    assert issubclass(ChunkEngineError, SecureSyncError)


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


def test_chunk_engine_error_carries_message_and_cause() -> None:
    """Chaining preserves the original cause via `__cause__`."""
    cause = OSError("no space left on device")
    try:
        try:
            raise cause
        except OSError as exc:
            raise ChunkEngineError("Failed to write chunk") from exc
    except ChunkEngineError as error:
        assert str(error) == "Failed to write chunk"
        assert error.__cause__ is cause
