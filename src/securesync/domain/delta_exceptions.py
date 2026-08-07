"""Domain-level exceptions for delta synchronization.

These exceptions describe failures in terms the domain understands (an
attempt to diff manifests of two different files, a chunk missing the
hash it needs to be compared) without any knowledge of the concrete
technology that produced the manifests being compared — see
``docs/adr/0009-content-addressable-delta-computation.md``.
"""

from __future__ import annotations


class DeltaSyncError(Exception):
    """Base class for all delta-sync domain errors."""


class IncompatibleBaselineError(DeltaSyncError):
    """Raised when a baseline manifest can't be diffed against the current one.

    Comparing manifests only makes sense when both describe the same
    logical file — e.g. comparing a baseline loaded for ``a.txt``
    against a freshly computed manifest for ``b.txt`` is a caller bug,
    not a legitimate "everything changed" result.
    """


class UnhashedChunkError(DeltaSyncError):
    """Raised when a chunk in the current manifest has no recorded hash.

    :class:`~securesync.domain.chunk.ChunkCollection` structurally
    permits ``chunk_hash is None`` (it's the state a
    :class:`~securesync.domain.chunking.ChunkReader` yields before
    hashing), but a delta computation cannot classify a chunk it can't
    compare — every chunk fed into
    :class:`~securesync.domain.delta.DeltaCalculator` must already be
    hashed.
    """
