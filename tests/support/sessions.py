"""Test helpers for building real v2 sessions between two peers.

Transports no longer accept a hand-written ``(send_key, receive_key)`` pair:
they need a ``session_id``, a role, and keys produced by the real HKDF key
schedule. These helpers derive genuine sessions so transport tests exercise the
same code path production does.
"""

from __future__ import annotations

from securesync.infrastructure.networking.replay_protection import (
    ROLE_INITIATOR,
    ROLE_RESPONDER,
)
from securesync.infrastructure.networking.session_keys import derive_session_keys
from securesync.infrastructure.networking.session_store import PeerSession, SessionStore

#: Fixed handshake material so tests are deterministic.
SHARED_SECRET = b"\x42" * 32
SALT = b"\x07" * 16
INITIATOR_EPHEMERAL_PUB = b"\xa1" * 32
RESPONDER_EPHEMERAL_PUB = b"\xb2" * 32


def paired_sessions(
    *,
    initiator_id: str = "dev-a",
    responder_id: str = "dev-b",
    initiator_transfer_port: int = 0,
    initiator_manifest_port: int = 0,
    responder_transfer_port: int = 0,
    responder_manifest_port: int = 0,
    shared_secret: bytes = SHARED_SECRET,
    salt: bytes = SALT,
) -> tuple[PeerSession, PeerSession]:
    """Derive a matching ``(initiator_session, responder_session)`` pair.

    Both sessions are pre-confirmed so a transport can send immediately; the
    confirmation transition itself is covered by the session-store and security
    tests.

    Returns:
        ``(session_for_a, session_for_b)`` where ``a`` is the initiator.
    """
    a_keys = derive_session_keys(
        shared_secret=shared_secret,
        salt=salt,
        initiator_id=initiator_id,
        responder_id=responder_id,
        initiator_ephemeral_pub=INITIATOR_EPHEMERAL_PUB,
        responder_ephemeral_pub=RESPONDER_EPHEMERAL_PUB,
        role=ROLE_INITIATOR,
    )
    b_keys = derive_session_keys(
        shared_secret=shared_secret,
        salt=salt,
        initiator_id=initiator_id,
        responder_id=responder_id,
        initiator_ephemeral_pub=INITIATOR_EPHEMERAL_PUB,
        responder_ephemeral_pub=RESPONDER_EPHEMERAL_PUB,
        role=ROLE_RESPONDER,
    )
    session_a = PeerSession(
        peer_id=responder_id,
        session_id=a_keys.session_id,
        role=ROLE_INITIATOR,
        send_key=a_keys.send_key,
        receive_key=a_keys.receive_key,
        transfer_port=responder_transfer_port,
        manifest_port=responder_manifest_port,
        confirmed=True,
    )
    session_b = PeerSession(
        peer_id=initiator_id,
        session_id=b_keys.session_id,
        role=ROLE_RESPONDER,
        send_key=b_keys.send_key,
        receive_key=b_keys.receive_key,
        transfer_port=initiator_transfer_port,
        manifest_port=initiator_manifest_port,
        confirmed=True,
    )
    return session_a, session_b


def stores_with_pair(
    *,
    initiator_id: str = "dev-a",
    responder_id: str = "dev-b",
    initiator_transfer_port: int = 0,
    initiator_manifest_port: int = 0,
    responder_transfer_port: int = 0,
    responder_manifest_port: int = 0,
) -> tuple[SessionStore, SessionStore]:
    """Return two separate stores, each holding that device's own session."""
    session_a, session_b = paired_sessions(
        initiator_id=initiator_id,
        responder_id=responder_id,
        initiator_transfer_port=initiator_transfer_port,
        initiator_manifest_port=initiator_manifest_port,
        responder_transfer_port=responder_transfer_port,
        responder_manifest_port=responder_manifest_port,
    )
    store_a, store_b = SessionStore(), SessionStore()
    store_a.put(session_a)
    store_b.put(session_b)
    return store_a, store_b
