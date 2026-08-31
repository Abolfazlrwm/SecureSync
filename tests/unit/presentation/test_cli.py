"""Unit tests for the SecureSync CLI (presentation/cli.py).

Every command that touches "the user's home directory" is redirected
to a pytest ``tmp_path`` via monkeypatching ``Path.home`` — no test
here reads or writes anything under the real home directory.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from securesync.presentation.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _fake_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Redirect every ``Path.home()`` call in the CLI to a temp directory.

    ``_load_config``, ``peers``, ``init``'s default ``--storage-dir``,
    and ``trust``'s default all resolve through ``Path.home()`` (either
    directly or via the ``~`` in their default option values, which
    ``Path.expanduser()`` also consults). Patching ``Path.home`` covers
    both call shapes.
    """
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    # Also keep cwd-based config lookup (the second candidate in
    # `_load_config`) out of the real working directory.
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestConfigCommand:
    def test_no_config_file_exits_with_error(self) -> None:
        result = runner.invoke(app, ["config"])

        assert result.exit_code == 1
        assert "No config file found" in result.stdout
        assert "securesync init" in result.stdout

    def test_shows_redacted_device_id_by_default(self, _fake_home: Path) -> None:
        config_dir = _fake_home / ".securesync"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yaml").write_text(
            yaml.dump({"device_id": "abcdef1234567890", "log_level": "INFO"})
        )

        result = runner.invoke(app, ["config"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["device_id"] == "abcd..."
        assert payload["log_level"] == "INFO"

    def test_show_keys_flag_reveals_full_device_id(self, _fake_home: Path) -> None:
        config_dir = _fake_home / ".securesync"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yaml").write_text(yaml.dump({"device_id": "abcdef1234567890"}))

        result = runner.invoke(app, ["config", "--show-keys"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["device_id"] == "abcdef1234567890"

    def test_config_without_device_id_is_unaffected_by_redaction(self, _fake_home: Path) -> None:
        config_dir = _fake_home / ".securesync"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yaml").write_text(yaml.dump({"log_level": "DEBUG"}))

        result = runner.invoke(app, ["config"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload == {"log_level": "DEBUG"}


class TestPeersCommand:
    def test_no_trusted_peers_file(self) -> None:
        result = runner.invoke(app, ["peers"])

        assert result.exit_code == 0
        assert "no trusted peers configured" in result.stdout

    def test_lists_trusted_peers_with_truncated_key(self, _fake_home: Path) -> None:
        storage = _fake_home / ".securesync"
        storage.mkdir(parents=True)
        (storage / "trusted_peers.json").write_text(
            json.dumps({"device-a": "0123456789abcdef", "device-b": "fedcba9876543210"})
        )

        result = runner.invoke(app, ["peers"])

        assert result.exit_code == 0
        assert "device-a: 01234567..." in result.stdout
        assert "device-b: fedcba98..." in result.stdout


class TestSyncCommand:
    def test_no_paths_syncs_entire_root(self) -> None:
        result = runner.invoke(app, ["sync"])

        assert result.exit_code == 0
        assert "Syncing entire sync root..." in result.stdout
        assert "Would sync:" not in result.stdout

    def test_explicit_paths_are_each_reported(self) -> None:
        result = runner.invoke(app, ["sync", "a.txt", "b/c.txt"])

        assert result.exit_code == 0
        assert "Would sync: a.txt" in result.stdout
        assert "Would sync: b/c.txt" in result.stdout
        assert "Syncing entire sync root..." not in result.stdout


class TestPullCommand:
    def test_pull_without_from_device(self) -> None:
        result = runner.invoke(app, ["pull", "a.txt"])

        assert result.exit_code == 0
        assert "Would pull a.txt" in result.stdout
        assert "from" not in result.stdout

    def test_pull_with_from_device(self) -> None:
        result = runner.invoke(app, ["pull", "a.txt", "--from", "device-42"])

        assert result.exit_code == 0
        assert "Would pull a.txt from device-42" in result.stdout

    def test_pull_requires_at_least_one_path(self) -> None:
        result = runner.invoke(app, ["pull"])

        assert result.exit_code != 0


class TestInitCommand:
    def test_generates_identity_and_config(self, tmp_path: Path) -> None:
        target = tmp_path / "device-storage"

        result = runner.invoke(app, ["init", "--storage-dir", str(target)])

        assert result.exit_code == 0
        assert (target / "identity.private").exists()
        assert (target / "config.yaml").exists()
        assert "Fingerprint:" in result.stdout

        written = yaml.safe_load((target / "config.yaml").read_text())
        assert written["device_id"] == "auto"
        assert written["network"]["port"] == 8080

    def test_init_is_idempotent_and_reuses_identity(self, tmp_path: Path) -> None:
        target = tmp_path / "device-storage"

        first = runner.invoke(app, ["init", "--storage-dir", str(target)])
        second = runner.invoke(app, ["init", "--storage-dir", str(target)])

        assert first.exit_code == 0
        assert second.exit_code == 0
        # Same identity file -> same fingerprint reported both times.
        first_fp = [line for line in first.stdout.splitlines() if "Fingerprint" in line]
        second_fp = [line for line in second.stdout.splitlines() if "Fingerprint" in line]
        assert first_fp == second_fp


class TestTrustCommand:
    def test_no_trust_file_exits_with_error(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["trust", "device-a", "--storage-dir", str(tmp_path / "nope")])

        assert result.exit_code == 1
        assert "No trusted peers file found" in result.stdout

    def test_unknown_device_exits_with_error(self, tmp_path: Path) -> None:
        storage = tmp_path / "storage"
        storage.mkdir()
        (storage / "trusted_peers.json").write_text(json.dumps({"device-a": "abcd1234"}))

        result = runner.invoke(app, ["trust", "device-unknown", "--storage-dir", str(storage)])

        assert result.exit_code == 1
        assert "not in the trust store" in result.stdout
        # Untouched: the known device is still there.
        assert json.loads((storage / "trusted_peers.json").read_text()) == {"device-a": "abcd1234"}

    def test_removes_known_device(self, tmp_path: Path) -> None:
        storage = tmp_path / "storage"
        storage.mkdir()
        (storage / "trusted_peers.json").write_text(
            json.dumps({"device-a": "abcd1234", "device-b": "ef567890"})
        )

        result = runner.invoke(app, ["trust", "device-a", "--storage-dir", str(storage)])

        assert result.exit_code == 0
        assert "Trust reset for device: device-a" in result.stdout
        remaining = json.loads((storage / "trusted_peers.json").read_text())
        assert remaining == {"device-b": "ef567890"}


class TestDaemonCommand:
    def test_daemon_reports_bootstrap_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A failure inside bootstrap() is caught and reported, not a raw traceback."""

        async def _boom(_config_path: str) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr("securesync.main.bootstrap", _boom)

        result = runner.invoke(app, ["daemon", "--config", "config.yaml"])

        assert result.exit_code == 1
        assert "Error: boom" in result.stderr

    def test_daemon_handles_keyboard_interrupt_cleanly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ctrl+C during the daemon run exits cleanly instead of a traceback."""

        async def _interrupted(_config_path: str) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr("securesync.main.bootstrap", _interrupted)

        result = runner.invoke(app, ["daemon"])

        assert result.exit_code == 0
        assert "Shutting down..." in result.stdout


class TestVersionAndHelp:
    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["--version"])

        assert result.exit_code == 0
        assert "securesync" in result.stdout

    def test_version_flag_falls_back_when_package_metadata_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An editable/uninstalled checkout shouldn't crash `--version`."""

        def _raise_not_found(_name: str) -> str:
            raise ModuleNotFoundError("no metadata")

        monkeypatch.setattr("importlib.metadata.version", _raise_not_found)

        result = runner.invoke(app, ["--version"])

        assert result.exit_code == 0
        assert "securesync (version unknown)" in result.stdout

    def test_no_subcommand_shows_help(self) -> None:
        result = runner.invoke(app, [])

        assert result.exit_code == 0
        assert "Run 'securesync <command> --help'" in result.stdout
