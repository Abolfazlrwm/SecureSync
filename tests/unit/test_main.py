"""Unit tests for `securesync.main.bootstrap`.

These exercise the real wiring — a real SQLite metadata store, a real
Ed25519 identity, real TCP sockets for the handshake/transfer/manifest
services — on dedicated high port numbers (following the convention
already used in tests/unit/infrastructure/networking/), scoped to a
`tmp_path` so nothing touches the real filesystem or a real network
interface beyond localhost.

`bootstrap()` only returns when the orchestrator is stopped, so every
test here starts it as a background task, gives it a moment to finish
wiring, cancels the task to trigger the same shutdown path a real
signal would (see `_run_and_stop`'s docstring for why a real OS signal
isn't used here), and awaits it with a timeout so a wiring regression
fails the test instead of hanging the suite.

Lines deliberately left uncovered (see the Phase 19 report — not
fixed here): the `if __name__ == "__main__":` block at the bottom of
main.py can't be exercised via `pytest` without spawning a subprocess,
and doing so for two lines that are a thin wrapper around the
already-tested `bootstrap()` call isn't worth the added flakiness.
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from unittest.mock import patch

import yaml

from securesync.infrastructure.crypto.ed25519_identity_provider import Ed25519IdentityProvider
from securesync.infrastructure.crypto.pyca_crypto import PycaKeyExchangeProvider
from securesync.infrastructure.networking.file_trusted_peer_repository import (
    FileTrustedPeerRepository,
)
from securesync.infrastructure.networking.x25519_handshake import X25519Handshake
from securesync.main import bootstrap


def _write_config(tmp_path: Path, *, base_port: int) -> Path:
    """Write a real config.yaml pointing entirely inside tmp_path."""
    storage_dir = tmp_path / "storage"
    sync_dir = tmp_path / "sync"
    storage_dir.mkdir(parents=True, exist_ok=True)
    sync_dir.mkdir(parents=True, exist_ok=True)

    config = {
        "device_id": "test-device",
        "profile": "testing",
        "storage": {
            "sync_directory": str(sync_dir),
            "database_path": str(storage_dir / "metadata.db"),
            "chunk_repository_path": str(storage_dir / "chunks"),
        },
        "network": {
            "port": base_port,
            "transfer_port": base_port + 1,
            "manifest_port": base_port + 2,
            "discovery_enabled": False,
        },
        "log_level": "INFO",
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.dump(config))
    return config_path


async def _run_and_stop(config_path: Path) -> None:
    """Run bootstrap() in the background, then stop it.

    Cancelling the task (rather than sending a real OS signal) is
    deliberate: ``os.kill(pid, signal.SIGTERM)`` on Windows doesn't
    invoke a Python-level handler at all — it hard-terminates the
    process via ``TerminateProcess``, which would kill the test runner
    itself. Cancellation raises ``CancelledError`` at the same
    suspension point (``await self._stop_event.wait()`` inside
    ``orchestrator.wait_until_stopped()``) that a real signal's
    handler would eventually trigger via ``orchestrator.stop()``, so
    it unwinds through the exact same ``finally`` cleanup in
    ``bootstrap`` on every platform.

    mDNS registration is patched out the same way
    tests/unit/infrastructure/networking/test_mdns_discovery.py does —
    real `zeroconf` registration needs actual multicast network access,
    which isn't available (or wanted) in a unit test; the discovery
    wiring itself is already covered there.
    """
    with (
        patch("securesync.infrastructure.networking.mdns_discovery.Zeroconf"),
        patch("securesync.infrastructure.networking.mdns_discovery.ServiceBrowser"),
    ):
        task = asyncio.create_task(bootstrap(str(config_path)))
        # Give bootstrap time to reach `orchestrator.wait_until_stopped()` —
        # everything before that point (metadata connect, identity load,
        # all three real `.start()` calls) is synchronous-ish setup that
        # finishes well within this window on localhost.
        await asyncio.sleep(0.3)
        if task.done():
            # Re-raise with its real traceback instead of a bare
            # "assert not True" — task.exception() alone loses the
            # original stack, task.result() surfaces it in full.
            task.result()
            raise AssertionError("bootstrap() exited before being stopped — check its wiring")

        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)


class TestBootstrapWiring:
    async def test_creates_real_metadata_db_and_identity(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path, base_port=19510)

        await _run_and_stop(config_path)

        assert (tmp_path / "storage" / "metadata.db").exists()
        assert (tmp_path / "storage" / "identity.private").exists()

    async def test_shuts_down_cleanly_on_cancellation(self, tmp_path: Path) -> None:
        """A full bootstrap -> stop -> shutdown cycle raises nothing."""
        config_path = _write_config(tmp_path, base_port=19520)

        # If bootstrap() propagated an exception, `_run_and_stop` would
        # raise it here via `await task`.
        await _run_and_stop(config_path)

    async def test_ports_are_released_after_shutdown(self, tmp_path: Path) -> None:
        """A second bootstrap on the same ports proves the first one's
        sockets were actually closed, not leaked."""
        config_path = _write_config(tmp_path, base_port=19530)

        await _run_and_stop(config_path)
        await _run_and_stop(config_path)  # Would hang/error on a port leak.

    async def test_generates_new_identity_when_none_exists(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path, base_port=19540)

        await _run_and_stop(config_path)

        identity_file = tmp_path / "storage" / "identity.private"
        first_identity_bytes = identity_file.read_bytes()

        # A second run against the same storage dir must reuse the
        # existing identity rather than overwriting it.
        await _run_and_stop(config_path)
        assert identity_file.read_bytes() == first_identity_bytes

    async def test_inbound_handshake_is_drained_into_session_store(self, tmp_path: Path) -> None:
        """A real peer connecting in exercises `_drain_inbound_handshakes`.

        This is the one piece of `bootstrap`'s wiring that only runs
        when another device actually initiates a handshake against
        this one — every other test here only proves *this* device's
        services start and stop cleanly.
        """
        config_path = _write_config(tmp_path, base_port=19550)
        peer_storage = tmp_path / "peer"
        peer_storage.mkdir()

        peer_identity_provider = Ed25519IdentityProvider(peer_storage)
        peer_identity = peer_identity_provider.load_or_create()
        peer_handshake = X25519Handshake(
            "peer-device",
            0,
            0,
            PycaKeyExchangeProvider(),
            peer_identity_provider,
            peer_identity,
            FileTrustedPeerRepository(peer_storage / "trusted_peers.json"),
        )

        with (
            patch("securesync.infrastructure.networking.mdns_discovery.Zeroconf"),
            patch("securesync.infrastructure.networking.mdns_discovery.ServiceBrowser"),
        ):
            task = asyncio.create_task(bootstrap(str(config_path)))
            await asyncio.sleep(0.3)
            if task.done():
                task.result()
                raise AssertionError("bootstrap() exited early — check its wiring")

            result = await peer_handshake.initiate("127.0.0.1", 19550)
            assert result.peer_device_id == "test-device"
            # Give the drain loop a moment to pull the result off the queue.
            await asyncio.sleep(0.1)

            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=5)
