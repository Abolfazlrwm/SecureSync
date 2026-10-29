"""Shared platform-detection helpers for test skip conditions.

Pulled out once the same `_running_as_root` check was about to be
copy-pasted into a third test file — see `CONTRIBUTING.md` on avoiding
duplicate logic. Used with `@pytest.mark.skipif` for POSIX-permission-
dependent tests, which must be skipped both on Windows (no POSIX
permission bits) and when running as root (which bypasses permission
checks entirely, making the test meaningless rather than failing).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def running_as_root() -> bool:
    """Whether the current process can bypass POSIX permission checks."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def symlink_dir_or_skip(link: Path, target: Path) -> None:
    """Create a directory symlink at ``link`` pointing to ``target``, or skip the test.

    Symlink creation needs privileges Windows does not grant by default
    (Developer Mode or elevation), so tests that depend on one must skip
    rather than fail there.

    Also skips when the call reports success but no link materializes.
    That is not hypothetical: some sandboxed filesystems accept the
    syscall and create nothing, which would silently turn a
    symlink-escape test into a test of an ordinary missing directory —
    a test that passes while proving nothing.

    Args:
        link: The path at which to create the symlink.
        target: The directory the link should point to.

    Raises:
        pytest.skip.Exception: If the platform or filesystem will not
            create a real symlink here.
    """
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - platform dependent
        pytest.skip(f"symlinks are not available on this platform: {exc}")

    if not link.is_symlink():  # pragma: no cover - environment dependent
        pytest.skip("symlink creation silently did not take effect on this filesystem")
