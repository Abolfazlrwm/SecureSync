"""Unit tests for `securesync.domain.chunking` ports."""

from __future__ import annotations

import inspect

import pytest

from securesync.domain.chunking import (
    ChunkHasher,
    ChunkingStrategy,
    ChunkReader,
    ChunkRepository,
    ChunkWriter,
)


class _MinimalStrategy(ChunkingStrategy):
    """The smallest possible concrete `ChunkingStrategy` — only overrides what's abstract."""

    @property
    def name(self) -> str:
        return "minimal"

    def next_cut(self, buffered: memoryview, *, at_eof: bool) -> int | None:
        return len(buffered) if at_eof and buffered else None


@pytest.mark.parametrize(
    "port",
    [ChunkingStrategy, ChunkReader, ChunkHasher, ChunkWriter, ChunkRepository],
)
def test_port_cannot_be_instantiated_directly(port: type) -> None:
    """Every chunking port is an abstract base class."""
    assert inspect.isabstract(port)


class TestChunkingStrategyDefaults:
    """Tests for `ChunkingStrategy`'s non-abstract default behavior."""

    def test_preferred_read_block_size_default_is_one_mebibyte(self) -> None:
        """A strategy that doesn't override the hint gets a 1 MiB default."""
        strategy = _MinimalStrategy()
        assert strategy.preferred_read_block_size == 1 * 1024 * 1024

    def test_name_is_required(self) -> None:
        """`name` is abstract; the minimal strategy must supply one."""
        assert _MinimalStrategy().name == "minimal"
