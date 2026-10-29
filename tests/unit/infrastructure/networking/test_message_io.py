"""Tests for the bounded, time-limited length-prefixed read primitive."""

from __future__ import annotations

import asyncio
import struct

import pytest

from securesync.infrastructure.networking.message_io import (
    MAX_MESSAGE_SIZE,
    MessageReadTimeoutError,
    OversizedMessageError,
    read_length_prefixed,
)


def _reader(data: bytes) -> asyncio.StreamReader:
    """Build a StreamReader pre-fed with ``data``."""
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def _reader_prefix_only(prefix_data: bytes) -> asyncio.StreamReader:
    """Build a StreamReader fed with the length prefix but no body."""
    reader = asyncio.StreamReader()
    reader.feed_data(prefix_data)
    return reader


class TestReadLengthPrefixed:
    async def test_normal_message(self) -> None:
        body = b"hello"
        reader = _reader(struct.pack(">I", len(body)) + body)
        result = await read_length_prefixed(reader, max_size=MAX_MESSAGE_SIZE)
        assert result == body

    async def test_rejects_oversized_declared_length(self) -> None:
        """A peer claiming a 1 GiB body is refused before reading anything."""
        prefix = struct.pack(">I", 1_073_741_824)
        reader = _reader(prefix)
        with pytest.raises(OversizedMessageError):
            await read_length_prefixed(reader, max_size=MAX_MESSAGE_SIZE)

    async def test_times_out_when_prefix_never_arrives(self) -> None:
        reader = asyncio.StreamReader()
        # Nothing fed — readexactly(LENGTH_PREFIX_SIZE) will stall forever.
        with pytest.raises(MessageReadTimeoutError):
            await read_length_prefixed(reader, max_size=MAX_MESSAGE_SIZE, read_timeout=0.01)

    async def test_times_out_when_body_never_arrives(self) -> None:
        prefix = struct.pack(">I", 64)
        reader = _reader_prefix_only(prefix)
        with pytest.raises(MessageReadTimeoutError):
            await read_length_prefixed(reader, max_size=MAX_MESSAGE_SIZE, read_timeout=0.01)

    async def test_incomplete_read_error_surfaces(self) -> None:
        """IncompleteReadError surfaces unchanged so callers log a dropped connection."""
        prefix = struct.pack(">I", 100)
        reader = _reader(prefix + b"only-five-bytes")
        with pytest.raises(asyncio.IncompleteReadError):
            await read_length_prefixed(reader, max_size=MAX_MESSAGE_SIZE)
