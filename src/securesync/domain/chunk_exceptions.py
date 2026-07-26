"""Domain-level exceptions for the chunk engine.

These exceptions describe failures in terms the domain understands (an
invalid chunk size, a missing chunk source, a hash mismatch) without
any knowledge of the concrete technology (``hashlib``, the OS
filesystem API, etc.) that ultimately raised them. Infrastructure
adapters are responsible for translating low-level failures into these
types where the failure has domain meaning; purely technological
failures are wrapped in ``shared.exceptions.ChunkEngineError`` instead
— see ``docs/adr/0007-chunk-engine-strategy-pattern-and-sync-core.md``.
"""

from __future__ import annotations


class ChunkingError(Exception):
    """Base class for all chunk-engine domain errors."""


class InvalidChunkSizeError(ChunkingError):
    """Raised when a configured or requested chunk size is not positive."""


class ChunkSourceNotFoundError(ChunkingError):
    """Raised when the file to be chunked does not exist."""


class ChunkSourceAccessError(ChunkingError):
    """Raised when the file to be chunked can't be opened or read.

    Covers permission errors and the source path not being a regular
    file, as well as I/O errors encountered partway through reading.
    """


class ChunkVerificationError(ChunkingError):
    """Raised when a chunk cannot be verified against a recorded hash.

    Distinct from a *failed* verification (which is a normal, expected
    ``False`` result — see
    :class:`~securesync.application.use_cases.verify_chunk.VerifyChunkUseCase`)
    — this is raised when verification cannot even be attempted, e.g.
    because the chunk has no recorded hash to compare against.
    """
