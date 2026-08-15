"""Domain port for establishing a secure per-peer session before transfer.

Sits between peer discovery and chunk transfer: before a chunk can
move to or from a peer, something must have negotiated the session
keys their `TransferTransport` needs. `SessionCoordinator` is that
something, kept behind a port so application-layer code (e.g.
:class:`~securesync.application.orchestration.SyncOrchestrator`)
depends on the *concept* of "make sure we have a session with this
peer" without depending on the concrete handshake mechanism — see
``docs/adr/0020-multi-peer-session-keys-and-main-py-wiring.md``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from securesync.domain.networking import Peer


class SessionCoordinator(ABC):
    """Ensures a secure session (negotiated transfer keys) exists for a peer."""

    @abstractmethod
    async def ensure_session(self, peer: Peer) -> None:
        """Establish a session with `peer` if one doesn't already exist.

        Idempotent: calling this again for a peer that already has a
        session does nothing.

        Args:
            peer: The peer to establish a session with.
        """
        raise NotImplementedError
