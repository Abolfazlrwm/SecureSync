"""Use case for discovering and tracking peers on the network."""

from __future__ import annotations

import structlog

from securesync.domain.networking import (
    DiscoveryService,
    Peer,
    PeerDiscoveryObserver,
    PeerRepository,
    PeerStatus,
)

logger = structlog.get_logger()


class DiscoverPeersUseCase(PeerDiscoveryObserver):
    """Orchestrates peer discovery and persistence.

    This use case subscribes to a discovery service and updates the
    peer repository whenever a peer is found or lost.
    """

    def __init__(
        self,
        discovery_service: DiscoveryService,
        peer_repository: PeerRepository,
    ) -> None:
        """Initialize the use case.

        Args:
            discovery_service: The service that finds peers on the network.
            peer_repository: The store for known peers.
        """
        self._discovery_service = discovery_service
        self._peer_repository = peer_repository

    async def start(self) -> None:
        """Start discovering peers."""
        self._discovery_service.subscribe(self)
        await self._discovery_service.start()
        logger.info("peer_discovery_started")

    async def stop(self) -> None:
        """Stop discovering peers."""
        await self._discovery_service.stop()
        self._discovery_service.unsubscribe(self)
        logger.info("peer_discovery_stopped")

    async def on_peer_discovered(self, peer: Peer) -> None:
        """Handle a discovered peer by saving it to the repository.

        Args:
            peer: The discovered peer.
        """
        # Mark as online since we just discovered it
        online_peer = Peer(
            identity=peer.identity,
            address=peer.address,
            capabilities=peer.capabilities,
            status=PeerStatus.ONLINE,
            last_seen=peer.last_seen,
        )
        await self._peer_repository.save(online_peer)
        logger.info(
            "peer_discovered",
            device_id=peer.device_id,
            hostname=peer.identity.hostname,
            address=f"{peer.address.ip_address}:{peer.address.port}",
        )

    async def on_peer_lost(self, device_id: str) -> None:
        """Handle a lost peer by updating its status in the repository.

        Args:
            device_id: The ID of the lost peer.
        """
        peer = await self._peer_repository.get_by_id(device_id)
        if peer:
            offline_peer = Peer(
                identity=peer.identity,
                address=peer.address,
                capabilities=peer.capabilities,
                status=PeerStatus.OFFLINE,
                last_seen=peer.last_seen,
            )
            await self._peer_repository.save(offline_peer)
            logger.info("peer_lost", device_id=device_id)
