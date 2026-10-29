"""Entry point for the SecureSync application."""

import asyncio
import contextlib
import signal
import socket
import sys
import uuid
from collections.abc import Callable
from pathlib import Path

import structlog

from securesync.application.orchestration import SyncOrchestrator
from securesync.application.use_cases.calculate_chunk_hashes import CalculateChunkHashesUseCase
from securesync.application.use_cases.chunk_file import ChunkFileUseCase
from securesync.application.use_cases.conflict_resolution import DetectConflictUseCase
from securesync.application.use_cases.discover_peers import DiscoverPeersUseCase
from securesync.application.use_cases.receive_pushed_files import ReceivePushedFilesUseCase
from securesync.application.use_cases.sync_file import SyncFileUseCase
from securesync.application.use_cases.transfer_chunks import (
    DownloadChunksUseCase,
    UploadChunksUseCase,
)
from securesync.domain.conflict import VersionVector
from securesync.domain.sync_direction import SyncDirectionResolver
from securesync.infrastructure.chunking.file_chunk_repository import FileChunkRepository
from securesync.infrastructure.chunking.local_file_reconstructor import LocalFileReconstructor
from securesync.infrastructure.chunking.sha256_hash_provider import SHA256HashProvider
from securesync.infrastructure.chunking.streaming_chunk_reader import (
    FixedSizeChunkingStrategy,
    StreamingChunkReader,
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
from securesync.infrastructure.networking.tcp_manifest_exchange import (
    TcpManifestExchangeTransport,
)
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
                manifest_port=result.peer_manifest_port,
            ),
        )


async def bootstrap(
    config_path: str, *, on_ready: Callable[[SyncOrchestrator], None] | None = None
) -> None:
    """Initialize and start the application.

    Args:
        config_path: Path to the YAML configuration file.
        on_ready: Optional hook called with the fully-wired
            `SyncOrchestrator` right after construction, before
            `start()`/`wait_until_stopped()` block this coroutine.
            Not used in normal operation (`__main__` never passes
            one) — it exists so tests can obtain a handle to a real,
            fully-wired orchestrator (e.g. to call
            `handle_peer_discovered` directly) without needing a real
            mDNS network to trigger discovery. Must not block.
    """
    logger.info("application_bootstrap_started", config_path=config_path)

    # 1. Load configuration.
    config = YamlConfigLoader.load(config_path)
    device_id = config.device_id or str(uuid.uuid4())
    hostname = socket.gethostname()

    # 2. Wire dependencies — every adapter here is a real implementation.
    metadata_repo = SqliteMetadataRepository(config.storage.database_path)
    await metadata_repo.connect()
    # One-off resolve() during startup bootstrap, not a hot loop — the
    # anyio/trio Path this rule wants isn't worth a new dependency here.
    storage_dir = Path(config.storage.database_path).resolve().parent  # noqa: ASYNC240

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
        config.network.manifest_port,
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

    # See ADR-0025/0026: `push` (unlike `pull`) has no request/response
    # round trip, so a background loop has to actively drain arriving
    # chunks and reconstruct each file itself, rather than waiting for
    # something to ask for them by hash the way `request_chunks` does.
    receive_pushed_files_use_case = ReceivePushedFilesUseCase(
        transport,
        Path(config.storage.sync_directory),
        LocalFileReconstructor(),
        metadata_repo,
        device_id,
        # Verifies every arriving chunk against the digest the sender
        # declared before a single byte is written (ADR-0027).
        SHA256HashProvider(),
    )
    receive_pushes_task = asyncio.create_task(receive_pushed_files_use_case.run_forever())

    # The local chunk manifests peers request are the same store
    # ComputeDeltaUseCase already reads baselines from (ADR-0010: this
    # repository already is SecureSync's persistent manifest store).
    chunk_repository = FileChunkRepository(storage_dir=storage_dir / "chunks")
    manifest_exchange = TcpManifestExchangeTransport(
        device_id,
        _LISTEN_HOST,
        config.network.manifest_port,
        cipher,
        session_keys,
        chunk_repository,
        Path(config.storage.sync_directory),
        metadata_lookup=metadata_repo,
    )
    await manifest_exchange.start()

    # The Phase 15-17 file-sync pipeline (manifest exchange + delta +
    # transfer + version-aware direction) was built and tested in
    # isolation but was never actually wired in here, which meant
    # SyncOrchestrator's auto-push-on-discovery (ADR-0023/0024) was a
    # silent no-op in every real run: `_auto_push_known_files` returns
    # immediately whenever `sync_file_use_case` is `None`. This wiring
    # is what makes peer discovery actually result in files moving.
    async def _local_version(relative_path: str) -> VersionVector | None:
        """Look up this device's own recorded version for a file.

        Lets `SyncFileUseCase.push` include a real version vector with
        each push (see ADR-0026) instead of leaving the receiving
        side's `ReceivePushedFilesUseCase` to fall back to inventing
        one from scratch.
        """
        existing = await metadata_repo.get_file_metadata(relative_path)
        return existing.version_vector if existing is not None else None

    sync_file_use_case = SyncFileUseCase(
        manifest_exchange=manifest_exchange,
        chunk_file_use_case=ChunkFileUseCase(StreamingChunkReader(), SHA256HashProvider()),
        calculate_hashes_use_case=CalculateChunkHashesUseCase(
            StreamingChunkReader(), SHA256HashProvider()
        ),
        upload_use_case=upload_use_case,
        chunk_repository=chunk_repository,
        file_reconstructor=LocalFileReconstructor(),
        local_version_provider=_local_version,
        direction_resolver=SyncDirectionResolver(),
    )
    chunking_strategy = FixedSizeChunkingStrategy(chunk_size=config.storage.chunk_size)

    orchestrator = SyncOrchestrator(
        metadata_repo=metadata_repo,
        discovery_use_case=discovery_use_case,
        conflict_use_case=conflict_use_case,
        download_use_case=download_use_case,
        upload_use_case=upload_use_case,
        session_coordinator=session_coordinator,
        sync_file_use_case=sync_file_use_case,
        sync_root=Path(config.storage.sync_directory),
        chunking_strategy=chunking_strategy,
        chunk_size=config.storage.chunk_size,
    )

    if on_ready is not None:
        on_ready(orchestrator)

    # 4. Handle signals.
    #
    # asyncio's loop.add_signal_handler() isn't implemented on Windows
    # (see https://docs.python.org/3/library/asyncio-platforms.html) —
    # it raises NotImplementedError immediately, which used to crash
    # bootstrap() at this exact line on every Windows run. Fall back to
    # signal.signal() there: it can't interrupt the loop mid-await the
    # way add_signal_handler can, but a Ctrl+C still raises
    # KeyboardInterrupt into asyncio.run() on Windows, which
    # presentation/cli.py's `daemon` command already catches — so
    # graceful shutdown still works, it just takes the KeyboardInterrupt
    # path there instead of orchestrator.stop() here.
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(orchestrator.stop()))
        except NotImplementedError:
            logger.warning(
                "signal_handler_unsupported",
                signal=sig.name,
                note="platform doesn't support loop.add_signal_handler (e.g. Windows); "
                "relying on KeyboardInterrupt for graceful shutdown instead",
            )

    # 5. Start the orchestrator and run until stopped.
    try:
        await orchestrator.start()
        await orchestrator.wait_until_stopped()
    finally:
        drain_task.cancel()
        receive_pushes_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await drain_task
        with contextlib.suppress(asyncio.CancelledError):
            await receive_pushes_task
        await manifest_exchange.stop()
        await transport.stop()
        await handshake_server.stop()
        await metadata_repo.close()
        logger.info("application_shutdown_complete")


if __name__ == "__main__":
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(bootstrap(config_file))
