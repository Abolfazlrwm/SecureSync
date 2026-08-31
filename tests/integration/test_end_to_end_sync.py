"""End-to-end test: two real `bootstrap()`'d SecureSync instances sync a
real file over real TCP, with real encryption, real identities, and a
real SQLite metadata store on each side — fully automatically, with no
manual intervention on the receiving side.

The one piece of a real deployment this test doesn't exercise is mDNS
discovery itself — `Zeroconf`/`ServiceBrowser` are patched out the same
way tests/unit/infrastructure/networking/test_mdns_discovery.py and
tests/unit/test_main.py do, since real multicast isn't available (or
wanted) in a test environment, and it already has its own dedicated
test. In its place, this test calls `handle_peer_discovered` directly
via `bootstrap`'s `on_ready` hook — everything downstream of "a peer
was discovered" (session handshake, manifest exchange, delta
computation, chunk transfer, and — as of Phase 21 — autonomous file
reconstruction) is the real production code path.

## History

Phase 20 first wrote this test and it immediately found three real
bugs (see ADR-0025): `main.py` never wired `SyncFileUseCase` into
`SyncOrchestrator` at all, `TcpTransferTransport` looked up sessions
under the wrong device_id, and `send_chunk` connected to the wrong
port. Even after fixing all three, this test still needed a manual
workaround on B's side (calling `DownloadChunksUseCase.execute`
directly) because nothing autonomously drained a pushed chunk and
reconstructed the file — `push` had no receiver, unlike `pull`.

Phase 21 built that receiver (`ReceivePushedFilesUseCase`, wired into
`bootstrap` as a background task — see ADR-0026) and this test was
rewritten to remove the workaround entirely: it now just writes a file
on A and polls for it to appear on B, the same way a person actually
using SecureSync would experience it.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import yaml

from securesync.application.orchestration import SyncOrchestrator
from securesync.domain.conflict import VersionVector
from securesync.domain.metadata import FileMetadata
from securesync.domain.networking import Peer, PeerAddress, PeerCapabilities, PeerIdentity
from securesync.main import bootstrap

_SYNC_TIMEOUT = 10.0
_POLL_INTERVAL = 0.1


def _write_config(tmp_path: Path, *, device_id: str, base_port: int) -> tuple[Path, Path]:
    """Write a real config.yaml for one device; return (config_path, sync_dir)."""
    storage_dir = tmp_path / device_id / "storage"
    sync_dir = tmp_path / device_id / "sync"
    storage_dir.mkdir(parents=True)
    sync_dir.mkdir(parents=True)

    config = {
        "device_id": device_id,
        "profile": "testing",
        "storage": {
            "sync_directory": str(sync_dir),
            "database_path": str(storage_dir / "metadata.db"),
            "chunk_repository_path": str(storage_dir / "chunks"),
            "chunk_size": 4 * 1024 * 1024,
        },
        "network": {
            "port": base_port,
            "transfer_port": base_port + 1,
            "manifest_port": base_port + 2,
            "discovery_enabled": False,
        },
        "log_level": "INFO",
    }
    config_path = tmp_path / device_id / "config.yaml"
    config_path.write_text(yaml.dump(config))
    return config_path, sync_dir


class _Device:
    """A running bootstrap()'d instance, captured via the on_ready hook."""

    def __init__(self, sync_dir: Path) -> None:
        self.sync_dir = sync_dir
        self.orchestrator: SyncOrchestrator | None = None
        self.task: asyncio.Task[None] | None = None
        self._ready = asyncio.Event()

    def _on_ready(self, orchestrator: SyncOrchestrator) -> None:
        self.orchestrator = orchestrator
        self._ready.set()

    async def wait_ready(self) -> None:
        await asyncio.wait_for(self._ready.wait(), timeout=5)

    async def stop(self) -> None:
        assert self.task is not None
        self.task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(self.task, timeout=5)


async def _start_device(config_path: Path, sync_dir: Path) -> _Device:
    """Start one real instance in the background and wait for it to be ready."""
    device = _Device(sync_dir)
    device.task = asyncio.create_task(bootstrap(str(config_path), on_ready=device._on_ready))
    await device.wait_ready()
    return device


async def _wait_for_file(
    path: Path, expected_bytes: bytes, timeout_seconds: float = _SYNC_TIMEOUT
) -> None:
    """Poll until `path` exists and matches `expected_bytes`, or time out.

    A plain polling loop over `pathlib.Path`, not `asyncio.timeout` or
    `anyio.Path` — this is a synchronous, blocking filesystem check
    (deliberately, since it's what actually happened on disk that
    matters here), just interleaved with real `asyncio.sleep` between
    checks so other tasks (the two real bootstrap()'d instances) keep
    running.

    Only checks the file itself — a caller that also needs to wait for
    the receiving device's metadata to be saved (a separate, later
    async step on that device's own background task) needs its own
    combined wait; see `test_file_created_on_a_syncs_to_b_automatically`
    for why checking the file alone isn't always enough.
    """
    elapsed = 0.0
    while elapsed < timeout_seconds:
        if path.exists() and path.read_bytes() == expected_bytes:  # noqa: ASYNC240
            return
        await asyncio.sleep(_POLL_INTERVAL)
        elapsed += _POLL_INTERVAL
    actual = path.read_bytes() if path.exists() else None  # noqa: ASYNC240
    raise AssertionError(
        f"{path} did not sync within {timeout_seconds}s "
        f"(exists={path.exists()}, content={actual!r}, expected={expected_bytes!r})"  # noqa: ASYNC240
    )


class TestEndToEndSync:
    async def test_file_created_on_a_syncs_to_b_automatically(self, tmp_path: Path) -> None:
        config_a, sync_a = _write_config(tmp_path, device_id="device-a", base_port=19610)
        config_b, sync_b = _write_config(tmp_path, device_id="device-b", base_port=19620)

        with (
            patch("securesync.infrastructure.networking.mdns_discovery.Zeroconf"),
            patch("securesync.infrastructure.networking.mdns_discovery.ServiceBrowser"),
        ):
            device_a = await _start_device(config_a, sync_a)
            device_b = await _start_device(config_b, sync_b)
            try:
                # Write a real file into A's sync directory, and record
                # it in A's real metadata store -- standing in for the
                # live filesystem watcher (Phase 1), which isn't wired
                # into main.py yet; that's a separate, already-tested
                # component (tests/integration/test_monitor_directories_integration.py).
                content = b"hello from device A, synced end to end\n"
                (sync_a / "hello.txt").write_bytes(content)
                assert device_a.orchestrator is not None
                await device_a.orchestrator.metadata_repo.save_file_metadata(
                    FileMetadata(
                        file_path="hello.txt",
                        version_vector=VersionVector({"device-a": 1}),
                        last_modified=datetime.now(UTC),
                    )
                )

                # Simulate B being discovered by A -- this triggers the
                # real handshake, real session establishment, direction
                # resolution (PUSH, since B has no manifest for this
                # file yet), and a real encrypted chunk delivered to
                # B's real listening socket.
                peer_b = Peer(
                    identity=PeerIdentity(
                        device_id="device-b", hostname="device-b-host", fingerprint="n/a"
                    ),
                    address=PeerAddress(ip_address="127.0.0.1", port=19620),
                    capabilities=PeerCapabilities(version="1.0"),
                )
                assert device_a.orchestrator is not None
                await device_a.orchestrator.handle_peer_discovered(peer_b)

                # No manual intervention on B's side needed as of Phase
                # 21: `ReceivePushedFilesUseCase` (running as a
                # background task inside B's own bootstrap()) drains
                # the pushed chunk and reconstructs the file itself.
                #
                # Wait for BOTH the file content AND B's metadata to be
                # in place, not just the file: `handle_peer_discovered`
                # returning on A's side only means the bytes were
                # written to the socket, not that B's independent
                # background task has finished processing them --
                # `write_chunk_at_offset` (file) and the metadata save
                # that follows it are two separate scheduling points on
                # B's task, and a slower/busier runner (this raced on a
                # real macOS GitHub Actions runner) can interleave the
                # test's own polling in between the two.
                assert device_b.orchestrator is not None

                async def _b_is_fully_synced() -> bool:
                    if not (sync_b / "hello.txt").exists():
                        return False
                    if (sync_b / "hello.txt").read_bytes() != content:
                        return False
                    meta = await device_b.orchestrator.metadata_repo.get_file_metadata("hello.txt")
                    return meta is not None

                elapsed = 0.0
                while elapsed < _SYNC_TIMEOUT:
                    if await _b_is_fully_synced():
                        break
                    await asyncio.sleep(_POLL_INTERVAL)
                    elapsed += _POLL_INTERVAL
                else:
                    raise AssertionError(
                        f"hello.txt did not fully sync (file + metadata) to B "
                        f"within {_SYNC_TIMEOUT}s"
                    )

                # And B's own metadata store reflects the sender's
                # version, ready to be reported back to A (or a third
                # device) as B's own up-to-date manifest.
                b_meta = await device_b.orchestrator.metadata_repo.get_file_metadata("hello.txt")
                assert b_meta is not None
                assert b_meta.version_vector.counters.get("device-a") == 1
            finally:
                await device_a.stop()
                await device_b.stop()
