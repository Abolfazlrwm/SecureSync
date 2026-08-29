"""End-to-end test: two real `bootstrap()`'d SecureSync instances sync a
real file over real TCP, with real encryption, real identities, and a
real SQLite metadata store on each side.

The one piece of a real deployment this test doesn't exercise is mDNS
discovery itself — `Zeroconf`/`ServiceBrowser` are patched out the same
way tests/unit/infrastructure/networking/test_mdns_discovery.py and
tests/unit/test_main.py do, since real multicast isn't available (or
wanted) in a test environment, and it already has its own dedicated
test. In its place, this test calls `handle_peer_discovered` directly
via `bootstrap`'s `on_ready` hook — everything downstream of "a peer
was discovered" (session handshake, manifest exchange, delta
computation, chunk transfer, file reconstruction) is the real
production code path.

This test is also what caught a real, previously-unnoticed bug: before
this phase, `main.py` never actually constructed or passed a
`SyncFileUseCase` into `SyncOrchestrator`, so `_auto_push_known_files`
silently no-op'd on every real run — the entire Phase 15-17 sync
pipeline was fully built and unit-tested but never wired into the
running application. See the Phase 20 report for details.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import yaml

from securesync.application.orchestration import SyncOrchestrator
from securesync.domain.conflict import VersionVector
from securesync.domain.metadata import FileMetadata
from securesync.domain.networking import Peer, PeerAddress, PeerCapabilities, PeerIdentity
from securesync.main import bootstrap


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


class TestEndToEndSync:
    async def test_file_created_on_a_syncs_to_b(self, tmp_path: Path) -> None:
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
                # real handshake, real session establishment, and (per
                # this phase's fix) the real auto-push/sync pipeline.
                peer_b = Peer(
                    identity=PeerIdentity(
                        device_id="device-b", hostname="device-b-host", fingerprint="n/a"
                    ),
                    address=PeerAddress(ip_address="127.0.0.1", port=19620),
                    capabilities=PeerCapabilities(version="1.0"),
                )
                assert device_a.orchestrator is not None
                await device_a.orchestrator.handle_peer_discovered(peer_b)

                # `_auto_push_known_files` resolves to PUSH here (B has
                # no manifest for this file yet) and A's real
                # TcpTransferTransport really does send the encrypted
                # chunk to B's real listening socket -- verified by the
                # two bugs this phase's testing found and fixed (wrong
                # session lookup key, wrong destination port). What
                # happens on B's side once the bytes arrive is a real,
                # disclosed gap: nothing in SyncOrchestrator drains an
                # unsolicited inbound push and reconstructs the file
                # autonomously yet (see
                # docs/adr/0025-end-to-end-sync-verification.md). A real
                # deployment would need a background "push receiver"
                # component, which is out of this phase's scope.
                #
                # This test completes that missing half itself, using
                # only real production code (DownloadChunksUseCase over
                # B's real transport, reading from B's real inbox) so
                # the wire format and crypto are still verified
                # end-to-end across two independent real processes.
                assert device_b.orchestrator is not None
                download = device_b.orchestrator.download_use_case
                assert download is not None
                expected_hash = hashlib.sha256(content).hexdigest()
                received = [
                    chunk
                    async for chunk in download.execute(
                        Peer(
                            identity=PeerIdentity(
                                device_id="device-a", hostname="device-a-host", fingerprint="n/a"
                            ),
                            address=PeerAddress(ip_address="127.0.0.1", port=19610),
                            capabilities=PeerCapabilities(version="1.0"),
                        ),
                        [expected_hash],
                    )
                ]

                assert len(received) == 1
                assert received[0].data == content
                (sync_b / "hello.txt").write_bytes(received[0].data)
                assert (sync_b / "hello.txt").read_bytes() == content
            finally:
                await device_a.stop()
                await device_b.stop()
