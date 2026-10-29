"""Unit tests for the peer-path validation helper.

These cover the spelling rules in isolation (fast, no filesystem
needed). The end-to-end attack tests live in ``tests/security/`` and
drive the real receiver; these exist so a regression names the exact
rule that broke.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from securesync.shared.safe_path import (
    MAX_RELATIVE_PATH_LENGTH,
    UnsafePathError,
    resolve_within,
)
from tests.platform import symlink_dir_or_skip


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """A sync root that exists on disk."""
    sync = tmp_path / "sync"
    sync.mkdir()
    return sync


class TestAcceptedPaths:
    def test_simple_filename(self, root: Path) -> None:
        assert resolve_within(root, "notes.txt") == root / "notes.txt"

    def test_nested_path(self, root: Path) -> None:
        assert resolve_within(root, "a/b/c.txt") == root / "a" / "b" / "c.txt"

    def test_dot_segments_are_harmless(self, root: Path) -> None:
        assert resolve_within(root, "./a/./b.txt") == root / "a" / "b.txt"

    def test_dotdot_inside_a_filename_is_not_a_component(self, root: Path) -> None:
        # "a..b.txt" contains ".." as a substring but not as a path
        # component, so it is an ordinary filename and must be allowed.
        assert resolve_within(root, "a..b.txt") == root / "a..b.txt"

    def test_result_is_resolved(self, root: Path) -> None:
        assert resolve_within(root, "x.txt") == (root / "x.txt").resolve()


class TestRejectedPaths:
    @pytest.mark.parametrize(
        "relative_path",
        [
            pytest.param("", id="empty"),
            pytest.param("../escaped.txt", id="dotdot"),
            pytest.param("a/../../escaped.txt", id="nested-dotdot"),
            pytest.param("a/..", id="trailing-dotdot"),
            pytest.param("..\\escaped.txt", id="dotdot-backslash"),
            pytest.param("/etc/passwd", id="posix-absolute"),
            pytest.param("C:\\Windows\\evil.txt", id="windows-drive"),
            pytest.param("C:evil.txt", id="windows-drive-relative"),
            pytest.param("\\\\server\\share\\evil.txt", id="unc"),
            pytest.param("//server/share/evil.txt", id="posix-double-slash"),
            pytest.param("bad\x00name.txt", id="nul-byte"),
        ],
    )
    def test_rejects(self, root: Path, relative_path: str) -> None:
        with pytest.raises(UnsafePathError):
            resolve_within(root, relative_path)

    def test_rejects_overlong_path(self, root: Path) -> None:
        with pytest.raises(UnsafePathError):
            resolve_within(root, "a" * (MAX_RELATIVE_PATH_LENGTH + 1))

    def test_rejects_symlink_pointing_outside_root(self, root: Path, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        symlink_dir_or_skip(root / "link", outside)

        with pytest.raises(UnsafePathError):
            resolve_within(root, "link/evil.txt")

    def test_rejects_sibling_directory_sharing_the_root_prefix(
        self, root: Path, tmp_path: Path
    ) -> None:
        """The case a ``str.startswith`` check gets wrong.

        ``/tmp/.../sync-evil`` begins with the string ``/tmp/.../sync``
        while being a completely different directory, so a prefix
        comparison accepts it. Reachable in practice through a symlink
        inside the root.
        """
        sibling = tmp_path / "sync-evil"
        sibling.mkdir()
        symlink_dir_or_skip(root / "link", sibling)

        with pytest.raises(UnsafePathError):
            resolve_within(root, "link/evil.txt")

    def test_error_is_a_value_error(self, root: Path) -> None:
        """Callers that already treated a bad path as ``ValueError`` keep working."""
        assert issubclass(UnsafePathError, ValueError)
