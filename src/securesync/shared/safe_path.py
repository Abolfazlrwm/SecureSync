"""Validation of peer-supplied relative paths.

Every path that arrives over the network is attacker-controlled. A peer
names a file relative to *its own* sync root (see
``docs/adr/0022-file-synchronization-use-case.md``), and this device
turns that name into an absolute path under *its* sync root. That
translation is the one place where a remote string becomes a local
filesystem operation, so it gets its own module with its own tests
rather than being repeated as an ad-hoc ``root / name`` join in each
caller.

Three callers used to do exactly that, with three different (and, in
the push receiver's case, non-existent) levels of validation. There is
now one implementation and one place to get it right.

What this rejects, and why each one matters:

``..`` components
    The obvious attack: ``../escaped.txt`` resolves outside the root.
    Checked under both separator conventions, because a Windows peer
    can send ``..\\escaped.txt`` to a POSIX host, where the backslash is
    an ordinary filename character and the path would otherwise be
    accepted as a single (harmless-looking) filename.

Absolute paths and drive letters
    ``root / "/etc/passwd"`` silently discards ``root``: joining an
    absolute path to another path does not nest it, it replaces it.
    Windows drive-relative forms (``C:foo``) and UNC paths
    (``\\\\host\\share``) are rejected by the same check, on every
    platform, so a peer's platform cannot change the meaning of a path
    this device accepts.

NUL bytes
    ``open()`` raises ``ValueError`` for an embedded NUL rather than
    ``OSError``, which historically escaped the caller's error handling
    and terminated the receiver's background task.

Symlink escapes
    A symlink *inside* the root that points outside it defeats every
    string-prefix check: the joined path really does begin with the
    root's own prefix. Only comparing fully resolved locations catches
    it, which is why the containment test below is
    :meth:`pathlib.Path.is_relative_to` on resolved paths and never a
    ``str.startswith`` comparison — ``/srv/sync-evil`` shares the
    prefix ``/srv/sync`` while being a different directory entirely.

The result is the *resolved* path, not the joined one: callers get a
canonical location that has already had ``..`` segments and symlinks
evaluated, so they cannot accidentally reintroduce either.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Final

from securesync.shared.exceptions import SecureSyncError

#: Longest relative path accepted from a peer. Well above any real
#: filename or nested sync path, low enough that a peer cannot spend
#: this device's memory on path parsing alone.
MAX_RELATIVE_PATH_LENGTH: Final = 4096


class UnsafePathError(SecureSyncError, ValueError):
    """Raised when a peer-supplied path escapes (or may escape) the sync root.

    Subclasses :class:`ValueError` so existing callers that already
    treat a bad path as a ``ValueError`` keep working unchanged.
    """


def resolve_within(root: Path, relative_path: str) -> Path:
    """Resolve ``relative_path`` against ``root``, guaranteeing the result stays inside it.

    Args:
        root: The directory the result must be contained by — a sync
            root in every current caller.
        relative_path: An untrusted, peer-supplied path relative to
            ``root``.

    Returns:
        The fully resolved absolute path, guaranteed to be ``root``
        itself or a descendant of it.

    Raises:
        UnsafePathError: If ``relative_path`` is empty, too long,
            contains a NUL byte, is absolute or drive-qualified under
            either platform's rules, contains a ``..`` component, or
            resolves (following symlinks) to a location outside
            ``root``.
    """
    _reject_unsafe_spelling(relative_path)

    root_resolved = root.resolve()
    resolved = (root_resolved / relative_path).resolve()
    if not resolved.is_relative_to(root_resolved):
        raise UnsafePathError(f"Path traversal rejected: {relative_path!r} escapes the sync root")
    return resolved


def _reject_unsafe_spelling(relative_path: str) -> None:
    """Reject paths that are unsafe by their spelling, before touching the filesystem.

    Kept separate from :func:`resolve_within`'s containment check so
    that a path which is *both* absolute and escaping is reported as
    absolute (the clearer diagnosis), and so the spelling rules are
    testable without a real directory tree.
    """
    if not relative_path:
        raise UnsafePathError("Path traversal rejected: empty path")

    if len(relative_path) > MAX_RELATIVE_PATH_LENGTH:
        raise UnsafePathError(
            f"Path traversal rejected: path exceeds {MAX_RELATIVE_PATH_LENGTH} characters"
        )

    if "\x00" in relative_path:
        raise UnsafePathError(f"Path traversal rejected: NUL byte in {relative_path!r}")

    windows_path = PureWindowsPath(relative_path)
    if windows_path.drive or windows_path.is_absolute():
        raise UnsafePathError(f"Path traversal rejected: absolute path {relative_path!r}")

    if PurePosixPath(relative_path).is_absolute():
        raise UnsafePathError(f"Path traversal rejected: absolute path {relative_path!r}")

    # Both conventions, because the separator that makes ``..`` a
    # parent reference on one platform is an ordinary character on the
    # other — and the sending platform is not known here.
    for separator_normalized in (relative_path, relative_path.replace("\\", "/")):
        if ".." in PurePosixPath(separator_normalized).parts:
            raise UnsafePathError(f"Path traversal rejected: '..' component in {relative_path!r}")
