"""``hashlib``-based SHA-256 implementation of the ``ChunkHasher`` port."""

from __future__ import annotations

import hashlib

from securesync.domain.chunk import ChunkAlgorithm, ChunkHash
from securesync.domain.chunking import ChunkHasher

#: Bounds how much of the input is exposed to a single ``hashlib``
#: ``update()`` call. Feeding a hasher its data via bounded
#: ``memoryview`` slices (never ``bytes`` slices, which copy) means a
#: single very large custom chunk size never needs one huge contiguous
#: hashing call, without ever materializing a second copy of the input.
_HASH_SUBBLOCK_SIZE = 1 * 1024 * 1024


class SHA256HashProvider(ChunkHasher):
    """Computes SHA-256 digests using only :mod:`hashlib` — no custom crypto."""

    def hash(self, data: bytes | memoryview) -> ChunkHash:
        """See :meth:`ChunkHasher.hash`.

        Deterministic: hashing identical bytes always yields an
        identical digest, since :mod:`hashlib`'s SHA-256 implementation
        is itself deterministic.
        """
        hasher = hashlib.sha256()
        view = data if isinstance(data, memoryview) else memoryview(data)
        for start in range(0, len(view), _HASH_SUBBLOCK_SIZE):
            hasher.update(view[start : start + _HASH_SUBBLOCK_SIZE])
        return ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=hasher.hexdigest())
