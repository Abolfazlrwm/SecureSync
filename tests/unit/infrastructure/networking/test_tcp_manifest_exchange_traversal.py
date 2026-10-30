"""Tests for the path traversal protection in TcpManifestExchangeTransport."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from securesync.infrastructure.networking.session_store import SessionStore
from securesync.infrastructure.networking.tcp_manifest_exchange import TcpManifestExchangeTransport


@pytest.fixture
def sync_dir(tmp_path: Path) -> Path:
    d = tmp_path / "sync"
    d.mkdir()
    (d / "hello.txt").write_text("hi")
    return d


@pytest.fixture
def transport(sync_dir: Path):
    chunk_repo = MagicMock()
    chunk_repo.load = lambda path: None

    return TcpManifestExchangeTransport(
        own_device_id="dev-a",
        listen_host="127.0.0.1",
        listen_port=9999,
        cipher=MagicMock(),
        sessions=SessionStore(),
        chunk_repository=chunk_repo,
        sync_root=sync_dir,
    )


class TestPathTraversalProtection:
    def test_rejects_dotdot_traversal(self, transport):
        with pytest.raises(ValueError, match="Path traversal rejected"):
            transport._safe_resolve("../../etc/passwd")

    def test_rejects_absolute_path(self, transport):
        with pytest.raises(ValueError, match="Path traversal rejected"):
            transport._safe_resolve("/etc/passwd")

    def test_accepts_simple_relative_path(self, transport, sync_dir):
        result = transport._safe_resolve("hello.txt")
        assert result == sync_dir / "hello.txt"

    def test_accepts_subdirectory_path(self, transport, sync_dir):
        sub = sync_dir / "sub"
        sub.mkdir()
        result = transport._safe_resolve("sub/file.txt")
        assert result == sub / "file.txt"

    def test_rejects_path_with_trailing_dotdot(self, transport):
        with pytest.raises(ValueError, match="Path traversal rejected"):
            transport._safe_resolve("foo/../../../secret")

    def test_rejects_path_ending_at_parent(self, transport, sync_dir):
        # Resolve to the parent dir of sync_root (not inside it) — should be rejected
        parent = sync_dir.parent
        with pytest.raises(ValueError, match="Path traversal rejected"):
            transport._safe_resolve(f"../{parent.name}/something")
