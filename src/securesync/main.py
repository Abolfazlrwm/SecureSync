"""Entry point for the SecureSync application."""

import asyncio
import hashlib
import signal
import socket
import sys
import uuid

import structlog

from securesync.application.orchestration import SyncOrchestrator
from securesync.application.use_cases.conflict_resolution import DetectConflictUseCase
from securesync.application.use_cases.discover_peers import DiscoverPeersUseCase
from securesync.infrastructure.config.yaml_config_loader import YamlConfigLoader
from securesync.infrastructure.metadata.sqlite_metadata_repository import SqliteMetadataRepository
from securesync.infrastructure.networking.in_memory_conflict_repository import (
    InMemoryConflictRepository,
)
from securesync.infrastructure.networking.in_memory_peer_repository import InMemoryPeerRepository
from securesync.infrastructure.networking.mdns_discovery import MdnsDiscoveryService

logger = structlog.get_logger()


async def bootstrap(config_path: str) -> None:
    """Initialize and start the application.

    Args:
        config_path: Path to the YAML configuration file.
    """
    logger.info("application_bootstrap_started", config_path=config_path)

    # 1. Load configuration.
    config = YamlConfigLoader.load(config_path)
    device_id = config.device_id or str(uuid.uuid4())
    hostname = socket.gethostname()
    # No persistent keypair/identity store exists yet (see
    # docs/adr/0016-in-process-encrypted-transport.md) — this is a
    # display-only stand-in for the public-key fingerprint peers will
    # eventually verify each other with, not a security credential.
    fingerprint = hashlib.sha256(device_id.encode("utf-8")).hexdigest()[:16]

    # 2. Wire dependencies — every adapter here is a real implementation.
    metadata_repo = SqliteMetadataRepository(config.storage.database_path)
    await metadata_repo.connect()

    discovery_service = MdnsDiscoveryService(
        device_id=device_id,
        hostname=hostname,
        fingerprint=fingerprint,
        port=config.network.port,
    )
    peer_repository = InMemoryPeerRepository()
    discovery_use_case = DiscoverPeersUseCase(discovery_service, peer_repository)

    conflict_repository = InMemoryConflictRepository()
    conflict_use_case = DetectConflictUseCase(conflict_repository)

    # No TransferTransport implementation exists for real cross-process
    # network I/O yet — InProcessTransferTransport (added alongside this
    # wiring) only connects peers sharing one Python process, useful for
    # tests and future same-host multi-instance setups, not this
    # single-instance entry point. download_use_case/upload_use_case stay
    # unset until a socket-based transport lands; SyncOrchestrator
    # degrades gracefully (discovery and metadata still run) rather than
    # silently pretending to transfer chunks it can't.
    orchestrator = SyncOrchestrator(
        metadata_repo=metadata_repo,
        discovery_use_case=discovery_use_case,
        conflict_use_case=conflict_use_case,
    )

    # 3. Handle signals.
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(orchestrator.stop()))

    # 4. Start the orchestrator and run until stopped.
    try:
        await orchestrator.start()
        await orchestrator.wait_until_stopped()
    finally:
        await metadata_repo.close()
        logger.info("application_shutdown_complete")


if __name__ == "__main__":
    import contextlib

    config_file = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(bootstrap(config_file))
