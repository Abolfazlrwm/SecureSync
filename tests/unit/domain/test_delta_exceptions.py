"""Unit tests for `securesync.domain.delta_exceptions`."""

from __future__ import annotations

import pytest

from securesync.domain.delta_exceptions import (
    DeltaSyncError,
    IncompatibleBaselineError,
    UnhashedChunkError,
)


@pytest.mark.parametrize("exception_type", [IncompatibleBaselineError, UnhashedChunkError])
def test_every_delta_error_derives_from_delta_sync_error(
    exception_type: type[DeltaSyncError],
) -> None:
    """Every domain delta error is catchable as the shared `DeltaSyncError` base."""
    assert issubclass(exception_type, DeltaSyncError)


def test_delta_sync_error_derives_from_exception() -> None:
    """`DeltaSyncError` is a plain `Exception`."""
    assert issubclass(DeltaSyncError, Exception)


def test_error_carries_message_and_cause() -> None:
    """Chaining preserves the original cause via `__cause__`."""
    cause = ValueError("bad manifest")
    try:
        try:
            raise cause
        except ValueError as exc:
            raise IncompatibleBaselineError("manifests describe different files") from exc
    except IncompatibleBaselineError as error:
        assert str(error) == "manifests describe different files"
        assert error.__cause__ is cause
