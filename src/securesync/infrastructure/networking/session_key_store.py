"""A registry of negotiated per-peer session keys and transfer ports.

Bridges :class:`~securesync.infrastructure.networking.x25519_handshake.HandshakeResult`
(one handshake, one peer) to
:class:`~securesync.infrastructure.networking.tcp_transport.TcpTransferTransport`
(one instance, many peers): every completed handshake's keys — and
the peer's advertised chunk-transfer port, exchanged as part of the
same handshake — are recorded here by `peer_device_id`, and the
transport looks them up per call instead of being constructed with a
single fixed key pair and a single fixed peer.
"""

from __future__ import annotations

from dataclasses import dataclass


class NoSessionKeyError(Exception):
    """Raised when a transport needs keys for a peer that hasn't completed a handshake yet."""


@dataclass(frozen=True, slots=True)
class PeerSession:
    """One peer's negotiated keys and chunk-transfer port.

    Attributes:
        send_key: Key to encrypt messages sent to this peer.
        receive_key: Key to decrypt messages received from this peer.
        transfer_port: The port this peer's `TcpTransferTransport`
            listens on for chunk transfer, learned from the handshake
            (not the same as the handshake port itself).
    """

    send_key: bytes
    receive_key: bytes
    transfer_port: int


class SessionKeyStore:
    """An in-memory `device_id -> PeerSession` registry."""

    def __init__(self) -> None:
        """Initialize an empty store."""
        self._sessions: dict[str, PeerSession] = {}

    def put(self, device_id: str, session: PeerSession) -> None:
        """Record the negotiated session for a peer.

        Args:
            device_id: The peer's device ID.
            session: The negotiated `PeerSession`.
        """
        self._sessions[device_id] = session

    def get(self, device_id: str) -> PeerSession:
        """Return the `PeerSession` for a peer.

        Args:
            device_id: The peer's device ID.

        Returns:
            The negotiated `PeerSession`.

        Raises:
            NoSessionKeyError: If no handshake has completed for this
                peer yet.
        """
        session = self._sessions.get(device_id)
        if session is None:
            raise NoSessionKeyError(
                f"no session for {device_id!r} — a handshake must complete first"
            )
        return session

    def has(self, device_id: str) -> bool:
        """Return whether a session is already recorded for `device_id`."""
        return device_id in self._sessions
