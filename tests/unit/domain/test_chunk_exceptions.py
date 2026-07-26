"""Unit tests for `securesync.domain.chunk_exceptions`."""

from __future__ import annotations

import pytest

from securesync.domain.chunk_exceptions import (
    ChunkingError,
    ChunkSourceAccessError,
    ChunkSourceNotFoundError,
    ChunkVerificationError,
    InvalidChunkSizeError,
)


@pytest.mark.parametrize(
    "exception_type",
    [
        InvalidChunkSizeError,
        ChunkSourceNotFoundError,
        ChunkSourceAccessError,
        ChunkVerificationError,
    ],
)
def test_every_chunk_error_derives_from_chunking_error(
    exception_type: type[ChunkingError],
) -> None:
    """Every domain chunk error is catchable as the shared `ChunkingError` base."""
    assert issubclass(exception_type, ChunkingError)


def test_chunking_error_derives_from_exception() -> None:
    """`ChunkingError` is a plain `Exception`."""
    assert issubclass(ChunkingError, Exception)


def test_error_carries_message_and_cause() -> None:
    """Chaining preserves the original cause via `__cause__`."""
    cause = OSError("permission denied")
    try:
        try:
            raise cause
        except OSError as exc:
            raise ChunkSourceAccessError("Failed to read chunk source") from exc
    except ChunkSourceAccessError as error:
        assert str(error) == "Failed to read chunk source"
        assert error.__cause__ is cause
