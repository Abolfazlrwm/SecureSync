"""Domain-level exceptions for conflict detection and resolution.

These exceptions describe failures in terms the domain understands (a
conflict record that was never saved, or has already been resolved)
without any knowledge of the concrete technology a
:class:`~securesync.domain.conflict.ConflictRepository` implementation
uses to persist conflicts.
"""

from __future__ import annotations


class ConflictError(Exception):
    """Base class for all domain conflict-resolution errors."""


class ConflictNotFoundError(ConflictError):
    """Raised when a referenced conflict record doesn't exist in the repository.

    Typically means the caller passed a stale or invalid
    ``conflict_id`` — e.g. one already deleted, or one from a
    different repository instance than the one currently injected.
    """
