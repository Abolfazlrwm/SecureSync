"""Unit tests for `securesync.infrastructure.chunking.sha256_hash_provider.SHA256HashProvider`."""

from __future__ import annotations

import hashlib
import os

import pytest

from securesync.domain.chunk import ChunkAlgorithm
from securesync.infrastructure.chunking.sha256_hash_provider import SHA256HashProvider


@pytest.fixture
def provider() -> SHA256HashProvider:
    """A fresh `SHA256HashProvider` for each test."""
    return SHA256HashProvider()


class TestHash:
    """Tests for `SHA256HashProvider.hash`."""

    def test_matches_hashlib_reference(self, provider: SHA256HashProvider) -> None:
        """The digest matches `hashlib.sha256` computed directly."""
        data = b"the quick brown fox jumps over the lazy dog"
        result = provider.hash(data)
        assert result.digest == hashlib.sha256(data).hexdigest()
        assert result.algorithm is ChunkAlgorithm.SHA256

    def test_empty_bytes_matches_known_sha256(self, provider: SHA256HashProvider) -> None:
        """The digest of empty input matches the well-known empty-string SHA-256."""
        result = provider.hash(b"")
        assert result.digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_hashing_same_bytes_twice_is_deterministic(self, provider: SHA256HashProvider) -> None:
        """Hashing identical input twice yields an identical digest."""
        data = os.urandom(4096)
        assert provider.hash(data) == provider.hash(data)

    def test_different_bytes_produce_different_digests(self, provider: SHA256HashProvider) -> None:
        """Different input produces a different digest (no accidental collision)."""
        assert provider.hash(b"a") != provider.hash(b"b")

    def test_accepts_bytes_input(self, provider: SHA256HashProvider) -> None:
        """A plain `bytes` object is accepted."""
        result = provider.hash(b"hello world")
        assert result.digest == hashlib.sha256(b"hello world").hexdigest()

    def test_accepts_memoryview_input(self, provider: SHA256HashProvider) -> None:
        """A `memoryview` is accepted and hashes identically to the equivalent bytes."""
        data = b"hello world"
        result = provider.hash(memoryview(data))
        assert result.digest == hashlib.sha256(data).hexdigest()

    def test_memoryview_and_bytes_produce_same_digest(self, provider: SHA256HashProvider) -> None:
        """Hashing the same content via `bytes` or `memoryview` is indistinguishable."""
        data = os.urandom(1024)
        assert provider.hash(data) == provider.hash(memoryview(data))

    def test_data_larger_than_sub_block_size_hashes_correctly(
        self, provider: SHA256HashProvider
    ) -> None:
        """Data spanning multiple internal sub-blocks still hashes correctly.

        `SHA256HashProvider` feeds `hashlib` in bounded sub-blocks; this
        confirms multi-block feeding reassembles the exact same digest
        as hashing the whole buffer in one call.
        """
        data = os.urandom(3 * 1024 * 1024 + 17)  # > 1 MiB sub-block, non-aligned remainder
        result = provider.hash(data)
        assert result.digest == hashlib.sha256(data).hexdigest()

    def test_memoryview_slice_of_larger_buffer_hashes_only_the_slice(
        self, provider: SHA256HashProvider
    ) -> None:
        """A memoryview slice hashes only its own bytes, not the whole backing buffer."""
        backing = bytearray(b"XXXXXhelloXXXXX")
        view = memoryview(backing)[5:10]
        result = provider.hash(view)
        assert result.digest == hashlib.sha256(b"hello").hexdigest()
