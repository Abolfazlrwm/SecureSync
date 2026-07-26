"""Unit tests for `FixedSizeChunkingStrategy`."""

from __future__ import annotations

import pytest

from securesync.domain.chunk_exceptions import InvalidChunkSizeError
from securesync.infrastructure.chunking.streaming_chunk_reader import (
    DEFAULT_CHUNK_SIZE,
    FixedSizeChunkingStrategy,
)


class TestConstruction:
    """Tests for constructing a `FixedSizeChunkingStrategy`."""

    def test_default_chunk_size_is_four_mebibytes(self) -> None:
        """The documented default is 4 MiB."""
        assert DEFAULT_CHUNK_SIZE == 4 * 1024 * 1024
        strategy = FixedSizeChunkingStrategy()
        assert strategy.chunk_size == DEFAULT_CHUNK_SIZE

    def test_custom_chunk_size_is_honored(self) -> None:
        """A custom chunk size overrides the default."""
        strategy = FixedSizeChunkingStrategy(chunk_size=1024)
        assert strategy.chunk_size == 1024

    @pytest.mark.parametrize("invalid_size", [0, -1, -1024])
    def test_non_positive_chunk_size_rejected(self, invalid_size: int) -> None:
        """Zero or negative chunk sizes raise `InvalidChunkSizeError`."""
        with pytest.raises(InvalidChunkSizeError, match="must be > 0"):
            FixedSizeChunkingStrategy(chunk_size=invalid_size)

    def test_name_is_fixed_size(self) -> None:
        """The strategy identifies itself as `"fixed-size"`."""
        assert FixedSizeChunkingStrategy().name == "fixed-size"

    def test_preferred_read_block_size_matches_chunk_size(self) -> None:
        """The read-block hint aligns with the configured chunk size."""
        strategy = FixedSizeChunkingStrategy(chunk_size=2048)
        assert strategy.preferred_read_block_size == 2048


class TestNextCut:
    """Tests for `FixedSizeChunkingStrategy.next_cut`."""

    def test_returns_none_while_buffer_below_chunk_size_and_not_eof(self) -> None:
        """No cut point is returned until enough bytes have accumulated."""
        strategy = FixedSizeChunkingStrategy(chunk_size=10)
        assert strategy.next_cut(memoryview(b"12345"), at_eof=False) is None

    def test_returns_chunk_size_once_buffer_reaches_it(self) -> None:
        """A cut is returned exactly at the configured chunk size."""
        strategy = FixedSizeChunkingStrategy(chunk_size=10)
        assert strategy.next_cut(memoryview(b"1" * 10), at_eof=False) == 10

    def test_returns_chunk_size_when_buffer_exceeds_it(self) -> None:
        """A cut is returned even if the buffer has more than one chunk's worth."""
        strategy = FixedSizeChunkingStrategy(chunk_size=10)
        assert strategy.next_cut(memoryview(b"1" * 25), at_eof=False) == 10

    def test_returns_partial_length_at_eof_with_short_buffer(self) -> None:
        """At EOF with fewer bytes than a full chunk, the whole buffer is the cut."""
        strategy = FixedSizeChunkingStrategy(chunk_size=10)
        assert strategy.next_cut(memoryview(b"123"), at_eof=True) == 3

    def test_returns_none_at_eof_with_empty_buffer(self) -> None:
        """At EOF with nothing buffered, there's nothing left to cut."""
        strategy = FixedSizeChunkingStrategy(chunk_size=10)
        assert strategy.next_cut(memoryview(b""), at_eof=True) is None

    def test_returns_chunk_size_at_eof_with_exact_buffer(self) -> None:
        """At EOF with exactly one chunk's worth buffered, the full chunk is cut."""
        strategy = FixedSizeChunkingStrategy(chunk_size=10)
        assert strategy.next_cut(memoryview(b"1" * 10), at_eof=True) == 10

    def test_single_byte_chunk_size(self) -> None:
        """A chunk size of 1 cuts after every single byte."""
        strategy = FixedSizeChunkingStrategy(chunk_size=1)
        assert strategy.next_cut(memoryview(b"x"), at_eof=False) == 1
