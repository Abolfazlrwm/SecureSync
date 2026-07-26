"""Property-based tests for the chunk engine's core invariants.

Uses Hypothesis to check structural properties hold across many
randomly generated inputs, complementing the fixed set of examples in
`tests/unit/` and `tests/chunking/` with broader, automatically
generated coverage of the same invariants.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from securesync.infrastructure.chunking.sha256_hash_provider import SHA256HashProvider
from securesync.infrastructure.chunking.streaming_chunk_reader import (
    FixedSizeChunkingStrategy,
    StreamingChunkReader,
)


def _write_and_chunk(
    data: bytes, chunk_size: int, tmp_path_factory: pytest.TempPathFactory
) -> list:  # type: ignore[type-arg]
    """Write `data` to a fresh temp file and chunk it with the given `chunk_size`."""
    target = tmp_path_factory.mktemp("chunk-property") / "f.bin"
    target.write_bytes(data)
    return list(StreamingChunkReader().read_chunks(target, FixedSizeChunkingStrategy(chunk_size)))


@given(data=st.binary(max_size=20_000), chunk_size=st.integers(min_value=1, max_value=4096))
@settings(max_examples=50, deadline=None)
def test_chunks_always_reconstruct_the_original_bytes(
    data: bytes, chunk_size: int, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """For any content and any chunk size, concatenating all chunks reproduces the input."""
    chunks = _write_and_chunk(data, chunk_size, tmp_path_factory)
    assert b"".join(chunk.data for chunk in chunks) == data


@given(
    data=st.binary(min_size=1, max_size=20_000), chunk_size=st.integers(min_value=1, max_value=4096)
)
@settings(max_examples=50, deadline=None)
def test_only_the_final_chunk_may_be_shorter_than_chunk_size(
    data: bytes, chunk_size: int, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Every chunk but the last is exactly `chunk_size`; the last is 1..chunk_size."""
    chunks = _write_and_chunk(data, chunk_size, tmp_path_factory)
    for chunk in chunks[:-1]:
        assert chunk.metadata.size == chunk_size
    assert 1 <= chunks[-1].metadata.size <= chunk_size


@given(data=st.binary(max_size=20_000), chunk_size=st.integers(min_value=1, max_value=4096))
@settings(max_examples=50, deadline=None)
def test_chunk_indices_and_offsets_are_always_contiguous(
    data: bytes, chunk_size: int, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Indices run 0..N-1 in order; each offset equals the sum of preceding sizes."""
    chunks = _write_and_chunk(data, chunk_size, tmp_path_factory)
    expected_offset = 0
    for expected_index, chunk in enumerate(chunks):
        assert chunk.metadata.index == expected_index
        assert chunk.metadata.offset == expected_offset
        expected_offset += chunk.metadata.size
    assert expected_offset == len(data)


@given(data=st.binary(max_size=20_000), chunk_size=st.integers(min_value=1, max_value=4096))
@settings(max_examples=50, deadline=None)
def test_no_chunk_ever_exceeds_the_configured_chunk_size(
    data: bytes, chunk_size: int, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """No chunk's size ever exceeds `chunk_size`, regardless of content or file size."""
    chunks = _write_and_chunk(data, chunk_size, tmp_path_factory)
    assert all(chunk.metadata.size <= chunk_size for chunk in chunks)


@given(data=st.binary(max_size=50_000))
@settings(max_examples=50)
def test_hashing_the_same_bytes_is_always_deterministic(data: bytes) -> None:
    """Hashing identical bytes twice always yields an identical digest."""
    provider = SHA256HashProvider()
    assert provider.hash(data) == provider.hash(data)


@given(data=st.binary(max_size=50_000))
@settings(max_examples=50)
def test_hashing_bytes_and_memoryview_of_the_same_content_agree(data: bytes) -> None:
    """Hashing via `bytes` or an equivalent `memoryview` always agrees."""
    provider = SHA256HashProvider()
    assert provider.hash(data) == provider.hash(memoryview(data))
