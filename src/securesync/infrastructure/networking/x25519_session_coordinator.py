"""X25519 implementation of the SessionCoordinator port.

Initiates a handshake (which exchanges each side's chunk-transfer
port as part of the same message, alongside keys and identity — see
``docs/adr/0020-multi-peer-session-keys-and-main-py-wiring.md``) and
records the result in a `SessionKeyStore` shared with whatever
`TcpTransferTransport` will use it.
"""

from __future__ import annotations

import structlog

from securesync.domain.handshake import SessionCoordinator
from securesync.domain.networking import Peer
from securesync.infrastructure.networking.session_key_store import PeerSession, SessionKeyStore
from securesync.infrastructure.networking.x25519_handshake import X25519Handshake

logger = structlog.get_logger(__name__)


class X25519SessionCoordinator(SessionCoordinator):
    """Initiates an `X25519Handshake` and records its result in a `SessionKeyStore`."""

    def __init__(self, handshake: X25519Handshake, session_keys: SessionKeyStore) -> None:
        """Initialize the coordinator.

        Args:
            handshake: Performs the initiator side of the handshake.
            session_keys: Where negotiated sessions are recorded,
                shared with whatever `TcpTransferTransport` will use them.
        """
        self._handshake = handshake
        self._session_keys = session_keys

    async def ensure_session(self, peer: Peer) -> None:
        """Handshake with `peer` if no session exists for it yet.

        Args:
            peer: The peer to establish a session with.
        """
        if self._session_keys.has(peer.device_id):
            return
        result = await self._handshake.initiate(peer.address.ip_address, peer.address.port)
        self._session_keys.put(
            result.peer_device_id,
            PeerSession(
                send_key=result.send_key,
                receive_key=result.receive_key,
                transfer_port=result.peer_transfer_port,
            ),
        )
        logger.info("session_established", peer_device_id=result.peer_device_id)
