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


def running_as_root() -> bool:
    """Whether the current process can bypass POSIX permission checks."""
    return hasattr(os, "geteuid") and os.geteuid() == 0
