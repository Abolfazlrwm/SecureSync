"""Entry point for the SecureSync application."""

import asyncio
import contextlib
import signal
import socket
import sys
import uuid
from pathlib import Path

import structlog

from securesync.application.orchestration import SyncOrchestrator
from securesync.application.use_cases.conflict_resolution import DetectConflictUseCase
from securesync.application.use_cases.discover_peers import DiscoverPeersUseCase
from securesync.application.use_cases.transfer_chunks import (
    DownloadChunksUseCase,
    UploadChunksUseCase,
)
from securesync.infrastructure.config.yaml_config_loader import YamlConfigLoader
from securesync.infrastructure.crypto.ed25519_identity_provider import Ed25519IdentityProvider
from securesync.infrastructure.crypto.pyca_crypto import (
    AesGcmCipher,
    PycaKeyExchangeProvider,
    PycaSessionKeyProvider,
)
from securesync.infrastructure.metadata.sqlite_metadata_repository import SqliteMetadataRepository
from securesync.infrastructure.networking.file_trusted_peer_repository import (
    FileTrustedPeerRepository,
)
from securesync.infrastructure.networking.in_memory_conflict_repository import (
    InMemoryConflictRepository,
)
from securesync.infrastructure.networking.in_memory_peer_repository import InMemoryPeerRepository
from securesync.infrastructure.networking.mdns_discovery import MdnsDiscoveryService
from securesync.infrastructure.networking.session_key_store import PeerSession, SessionKeyStore
from securesync.infrastructure.networking.tcp_transport import TcpTransferTransport
from securesync.infrastructure.networking.x25519_handshake import HandshakeServer, X25519Handshake
from securesync.infrastructure.networking.x25519_session_coordinator import (
    X25519SessionCoordinator,
)

logger = structlog.get_logger()

#: Interface to listen on for the handshake server and transfer transport.
_LISTEN_HOST = "0.0.0.0"  # noqa: S104 — SecureSync is meant to accept LAN peer connections


async def _drain_inbound_handshakes(
    handshake_server: HandshakeServer, session_keys: SessionKeyStore
) -> None:
    """Feed completed inbound (responder-side) handshakes into the shared session store.

    `X25519SessionCoordinator` only records sessions for handshakes
    *this* device initiates — this loop is the equivalent for
    handshakes other peers initiate against this device's
    `HandshakeServer`.
    """
    while True:
        result = await handshake_server.results.get()
        session_keys.put(
            result.peer_device_id,
            PeerSession(
                send_key=result.send_key,
                receive_key=result.receive_key,
                transfer_port=result.peer_transfer_port,
            ),
        )


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

    # 2. Wire dependencies — every adapter here is a real implementation.
    metadata_repo = SqliteMetadataRepository(config.storage.database_path)
    await metadata_repo.connect()
    storage_dir = Path(config.storage.database_path).resolve().parent

    identity_provider = Ed25519IdentityProvider(storage_dir)
    own_identity = identity_provider.load_or_create()
    # Real fingerprint now: the identity's own public key, not a
    # display-only hash of the device_id.
    fingerprint = own_identity.public_key.hex()[:16]

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

    # 3. Wire the real, authenticated, multi-peer transfer path.
    key_exchange = PycaKeyExchangeProvider()
    session_key_provider = PycaSessionKeyProvider()
    trusted_peers = FileTrustedPeerRepository(storage_dir / "trusted_peers.json")
    session_keys = SessionKeyStore()

    handshake = X25519Handshake(
        device_id,
        config.network.transfer_port,
        key_exchange,
        session_key_provider,
        identity_provider,
        own_identity,
        trusted_peers,
    )
    handshake_server = HandshakeServer(handshake)
    await handshake_server.start(_LISTEN_HOST, config.network.port)
    drain_task = asyncio.create_task(_drain_inbound_handshakes(handshake_server, session_keys))

    session_coordinator = X25519SessionCoordinator(handshake, session_keys)
    cipher = AesGcmCipher()
    transport = TcpTransferTransport(
        device_id, _LISTEN_HOST, config.network.transfer_port, cipher, session_keys
    )
    await transport.start()
    download_use_case = DownloadChunksUseCase(transport)
    upload_use_case = UploadChunksUseCase(transport)

    orchestrator = SyncOrchestrator(
        metadata_repo=metadata_repo,
        discovery_use_case=discovery_use_case,
        conflict_use_case=conflict_use_case,
        download_use_case=download_use_case,
        upload_use_case=upload_use_case,
        session_coordinator=session_coordinator,
    )

    # 4. Handle signals.
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(orchestrator.stop()))

    # 5. Start the orchestrator and run until stopped.
    try:
        await orchestrator.start()
        await orchestrator.wait_until_stopped()
    finally:
        drain_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await drain_task
        await transport.stop()
        await handshake_server.stop()
        await metadata_repo.close()
        logger.info("application_shutdown_complete")


if __name__ == "__main__":
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(bootstrap(config_file))
