"""X25519 implementation of the SessionCoordinator port.

Initiates a handshake (which exchanges each side's chunk-transfer
port as part of the same message, alongside keys and identity — see
``docs/adr/0020-multi-peer-session-keys-and-main-py-wiring.md``) and
records the resulting session in the shared
:class:`~securesync.infrastructure.networking.session_store.SessionStore`.
"""

from __future__ import annotations

import structlog

from securesync.domain.handshake import SessionCoordinator
from securesync.domain.networking import Peer
from securesync.infrastructure.networking.session_store import PeerSession, SessionStore
from securesync.infrastructure.networking.x25519_handshake import X25519Handshake

logger = structlog.get_logger(__name__)


class X25519SessionCoordinator(SessionCoordinator):
    """Initiates an `X25519Handshake` and records its result in a `SessionStore`."""

    def __init__(self, handshake: X25519Handshake, sessions: SessionStore) -> None:
        """Initialize the coordinator.

        Args:
            handshake: Performs the initiator side of the handshake.
            sessions: Where negotiated sessions are recorded, shared with
                whatever transports will use them.
        """
        self._handshake = handshake
        self._sessions = sessions

    async def ensure_session(self, peer: Peer) -> None:
        """Handshake with `peer` unless a confirmed session already exists.

        Args:
            peer: The peer to establish a session with.
        """
        if self._sessions.has_confirmed_session(peer.device_id):
            return
        result = await self._handshake.initiate(peer.address.ip_address, peer.address.port)
        self._sessions.put(
            PeerSession(
                peer_id=result.peer_device_id,
                session_id=result.session_id,
                role=result.role,
                send_key=result.send_key,
                receive_key=result.receive_key,
                transfer_port=result.peer_transfer_port,
                manifest_port=result.peer_manifest_port,
                # The initiator's session is confirmed as soon as the
                # responder's signed reply has verified — which `initiate`
                # has already done by the time it returns.
                confirmed=True,
            )
        )
        logger.info("session_established", peer_device_id=result.peer_device_id)
