"""Shared, cross-cutting exception types.

``domain/`` defines its own exceptions and never imports from here (it
depends on nothing). ``infrastructure/``, ``application/``, and ``core/``
use these as the common root for errors that cross a technology boundary
(a third-party library failing, an OS-level error, etc.), so callers can
catch ``SecureSyncError`` without needing to know which adapter raised it.
"""

from __future__ import annotations


class SecureSyncError(Exception):
    """Base class for all SecureSync infrastructure/application errors."""


class FileWatcherError(SecureSyncError):
    """Raised when the filesystem-watcher infrastructure adapter fails."""
