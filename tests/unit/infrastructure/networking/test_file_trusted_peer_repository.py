"""Unit tests for FileTrustedPeerRepository."""

from __future__ import annotations

from pathlib import Path

from securesync.infrastructure.networking.file_trusted_peer_repository import (
    FileTrustedPeerRepository,
)


class TestGetTrustedKey:
    """Tests for looking up a peer's pinned key."""

    async def test_unknown_peer_returns_none(self, tmp_path: Path) -> None:
        repo = FileTrustedPeerRepository(tmp_path / "trust.json")

        result = await repo.get_trusted_key("dev-a")

        assert result is None

    async def test_returns_none_when_the_store_file_does_not_exist_yet(
        self, tmp_path: Path
    ) -> None:
        repo = FileTrustedPeerRepository(tmp_path / "does-not-exist" / "trust.json")

        result = await repo.get_trusted_key("dev-a")

        assert result is None


class TestTrust:
    """Tests for pinning a peer's key."""

    async def test_trusted_key_is_retrievable(self, tmp_path: Path) -> None:
        repo = FileTrustedPeerRepository(tmp_path / "trust.json")
        key = b"k" * 32

        await repo.trust("dev-a", key)

        assert await repo.get_trusted_key("dev-a") == key

    async def test_persists_across_repository_instances(self, tmp_path: Path) -> None:
        path = tmp_path / "trust.json"
        key = b"k" * 32
        await FileTrustedPeerRepository(path).trust("dev-a", key)

        reloaded = FileTrustedPeerRepository(path)

        assert await reloaded.get_trusted_key("dev-a") == key

    async def test_trusting_a_second_peer_does_not_overwrite_the_first(
        self, tmp_path: Path
    ) -> None:
        repo = FileTrustedPeerRepository(tmp_path / "trust.json")
        key_a, key_b = b"a" * 32, b"b" * 32

        await repo.trust("dev-a", key_a)
        await repo.trust("dev-b", key_b)

        assert await repo.get_trusted_key("dev-a") == key_a
        assert await repo.get_trusted_key("dev-b") == key_b

    async def test_re_trusting_the_same_peer_updates_its_key(self, tmp_path: Path) -> None:
        repo = FileTrustedPeerRepository(tmp_path / "trust.json")
        old_key, new_key = b"o" * 32, b"n" * 32

        await repo.trust("dev-a", old_key)
        await repo.trust("dev-a", new_key)

        assert await repo.get_trusted_key("dev-a") == new_key

    async def test_creates_parent_directory_if_missing(self, tmp_path: Path) -> None:
        repo = FileTrustedPeerRepository(tmp_path / "nested" / "dir" / "trust.json")

        await repo.trust("dev-a", b"k" * 32)

        assert (tmp_path / "nested" / "dir" / "trust.json").exists()
