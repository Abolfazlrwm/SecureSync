"""Replayed-handshake investigation for Step 1e.

Answers, with real sockets and real crypto:

1. capture a legitimate hello and an authenticated frame;
2. make the responder lose the session (expiry / process restart);
3. replay the captured hello;
4. check whether the same keys come back, and whether the captured frame is
   then accepted.

This is what decides whether 1e needs an explicit anti-replay/freshness
mechanism on the hello, or whether the responder's fresh ephemeral already
covers it.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import struct
from pathlib import Path

import msgpack  # type: ignore[import-untyped]
import pytest

from securesync.core.protocol import CURRENT_VERSION, Packet, PacketHeader, PacketType
from securesync.infrastructure.crypto.ed25519_identity_provider import Ed25519IdentityProvider
from securesync.infrastructure.crypto.pyca_crypto import (
    AesGcmCipher,
    PycaKeyExchangeProvider,
)
from securesync.infrastructure.networking.file_trusted_peer_repository import (
    FileTrustedPeerRepository,
)
from securesync.infrastructure.networking.replay_protection import (
    FRAME_VERSION,
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    AntiReplayWindow,
    TimestampSkewError,
    UnknownSessionError,
    build_aad,
    derive_nonce,
    encode_frame,
    now_ms,
    outgoing_direction,
)
from securesync.infrastructure.networking.secure_channel import SecureChannel
from securesync.infrastructure.networking.session_store import PeerSession, SessionStore
from securesync.infrastructure.networking.x25519_handshake import (
    HandshakeServer,
    X25519Handshake,
)
from tests.support.sessions import paired_sessions

CIPHER = AesGcmCipher()
_LENGTH_PREFIX = ">I"


def _responder(device_id: str, storage_dir: Path) -> X25519Handshake:
    identity_provider = Ed25519IdentityProvider(storage_dir)
    return X25519Handshake(
        device_id,
        9000,
        9001,
        PycaKeyExchangeProvider(),
        identity_provider,
        identity_provider.load_or_create(),
        FileTrustedPeerRepository(storage_dir / "trust.json"),
    )


class RawInitiator:
    """A hand-built initiator that keeps the exact hello bytes it sent."""

    def __init__(self, device_id: str, storage_dir: Path) -> None:
        self.device_id = device_id
        self._provider = Ed25519IdentityProvider(storage_dir)
        self._identity = self._provider.load_or_create()
        self._key_exchange = PycaKeyExchangeProvider()

    def build_hello(self, *, device_id: str | None = None) -> bytes:
        """Build a signed hello exactly as `X25519Handshake.initiate` does."""
        _, public_key = self._key_exchange.generate_key_pair()
        salt = os.urandom(16)
        signature = self._provider.sign(self._identity.private_key, salt + public_key)
        message = {
            "device_id": device_id or self.device_id,
            "transfer_port": 9000,
            "manifest_port": 9001,
            "salt": salt,
            "public_key": public_key,
            "identity_public_key": self._identity.public_key,
            "signature": signature,
        }
        body = msgpack.packb(message)
        return struct.pack(_LENGTH_PREFIX, len(body)) + body


async def _exchange(host: str, port: int, wire_hello: bytes) -> dict[str, object]:
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(wire_hello)
        await writer.drain()
        prefix = await reader.readexactly(4)
        (length,) = struct.unpack(_LENGTH_PREFIX, prefix)
        body = await reader.readexactly(length)
        return msgpack.unpackb(body, raw=False)  # type: ignore[no-any-return]
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()


def _responder_session(result: object) -> PeerSession:
    return PeerSession(
        peer_id=result.peer_device_id,  # type: ignore[attr-defined]
        session_id=result.session_id,  # type: ignore[attr-defined]
        role=result.role,  # type: ignore[attr-defined]
        send_key=result.send_key,  # type: ignore[attr-defined]
        receive_key=result.receive_key,  # type: ignore[attr-defined]
        transfer_port=result.peer_transfer_port,  # type: ignore[attr-defined]
        manifest_port=result.peer_manifest_port,  # type: ignore[attr-defined]
        confirmed=False,
    )


def _frame_with_timestamp(
    session: PeerSession,
    *,
    own_id: str,
    counter: int,
    timestamp_ms: int,
    payload: dict[str, object],
) -> bytes:
    """Build a CHUNK_DATA frame with a chosen timestamp (for the skew probe)."""
    header = PacketHeader(
        version=CURRENT_VERSION,
        packet_type=PacketType.CHUNK_DATA,
        flags=0,
        message_id=counter,
        payload_length=0,
        timestamp=timestamp_ms,
        crc32=0,
    )
    framed = Packet(header=header, payload=payload).encode()
    direction = outgoing_direction(session.role)
    nonce = derive_nonce(direction, counter)
    aad = build_aad(
        FRAME_VERSION,
        direction,
        int(PacketType.CHUNK_DATA),
        session.session_id,
        own_id.encode("utf-8"),
        session.peer_id.encode("utf-8"),
    )
    encrypted = CIPHER.encrypt(framed, session.send_key, nonce, associated_data=aad)
    return encode_frame(
        direction=direction,
        packet_type=int(PacketType.CHUNK_DATA),
        session_id=session.session_id,
        nonce=nonce,
        ciphertext=encrypted.ciphertext,
        tag=encrypted.tag,
    )


class TestReplayedHello:
    """Does replaying a captured hello reproduce the captured session?"""

    async def test_replayed_hello_derives_a_different_session(self, tmp_path: Path) -> None:
        server = HandshakeServer(_responder("dev-b", tmp_path / "b"))
        await server.start("127.0.0.1", 19601)
        try:
            initiator = RawInitiator("dev-a", tmp_path / "a")
            hello = initiator.build_hello()

            reply_one = await _exchange("127.0.0.1", 19601, hello)
            first = await asyncio.wait_for(server.results.get(), timeout=2)

            # Session state is lost (expiry / restart); identity and trust
            # store persist. The captured hello is replayed byte for byte.
            replay_reply = await _exchange("127.0.0.1", 19601, hello)
            second = await asyncio.wait_for(server.results.get(), timeout=2)

            assert first.session_id != second.session_id, (  # type: ignore[attr-defined]
                "a replayed hello must not reproduce the captured session id"
            )
            assert second.role == ROLE_RESPONDER  # type: ignore[attr-defined]
            # The responder contributed a fresh ephemeral, which is what makes
            # the shared secret — and therefore the session id — different.
            assert replay_reply["public_key"] != reply_one["public_key"]
        finally:
            await server.stop()

    async def test_captured_frame_is_rejected_after_the_session_is_lost(
        self, tmp_path: Path
    ) -> None:
        server = HandshakeServer(_responder("dev-b", tmp_path / "b"))
        await server.start("127.0.0.1", 19602)
        store_b = SessionStore()
        try:
            initiator = RawInitiator("dev-a", tmp_path / "a")
            hello = initiator.build_hello()
            await _exchange("127.0.0.1", 19602, hello)
            first = await asyncio.wait_for(server.results.get(), timeout=2)

            store_b.put(_responder_session(first))
            channel_b = SecureChannel("dev-b", CIPHER, store_b)

            # The initiator's half, built from the responder's result: the
            # initiator's send key is the responder's receive key.
            initiator_session = PeerSession(
                peer_id="dev-b",
                session_id=first.session_id,  # type: ignore[attr-defined]
                role=ROLE_INITIATOR,
                send_key=first.receive_key,  # type: ignore[attr-defined]
                receive_key=first.send_key,  # type: ignore[attr-defined]
                transfer_port=0,
                manifest_port=0,
                confirmed=True,
            )
            store_a = SessionStore()
            store_a.put(initiator_session)
            channel_a = SecureChannel("dev-a", CIPHER, store_a)
            captured = channel_a.seal(initiator_session, PacketType.CHUNK_DATA, {"n": 1})

            # Sanity check: accepted while the session exists.
            assert channel_b.open(captured)[0].payload == {"n": 1}

            # Session disappears, then the hello is replayed.
            store_b.remove_by_peer("dev-a")
            await _exchange("127.0.0.1", 19602, hello)
            replayed = await asyncio.wait_for(server.results.get(), timeout=2)
            store_b.put(_responder_session(replayed))

            # The captured frame names the OLD session id, which is gone, so it
            # is dropped before decryption. Note this is a *consequence* of the
            # new session id, not an explicit hello anti-replay check.
            with pytest.raises(UnknownSessionError):
                channel_b.open(captured)
        finally:
            await server.stop()


class TestWhyTheImplicitPropertyMatters:
    """What a replay would achieve if the session id were reproducible."""

    def test_restored_state_accepts_a_captured_frame_until_the_timestamp_ages_out(
        self,
    ) -> None:
        session_a, session_b = paired_sessions()
        store_a = SessionStore()
        store_a.put(session_a)
        channel_a = SecureChannel("dev-a", CIPHER, store_a)
        captured = channel_a.seal(session_a, PacketType.CHUNK_DATA, {"n": 1})

        # "State restored": same id, same keys, fresh window, counters at 1 —
        # exactly what a same-id re-derivation would hand an attacker.
        store_b = SessionStore()
        store_b.put(_restored(session_b))
        channel_b = SecureChannel("dev-b", CIPHER, store_b)

        assert channel_b.open(captured)[0].payload == {"n": 1}

        # A captured frame that is older than the skew window is the only thing
        # left standing between a restored session and a successful replay.
        stale = _frame_with_timestamp(
            session_a,
            own_id="dev-a",
            counter=2,
            timestamp_ms=now_ms() - 600_000,
            payload={"n": 2},
        )
        with pytest.raises(TimestampSkewError):
            channel_b.open(stale)


class TestHelloFieldMalleability:
    """The hello signature covers `salt || ephemeral_pub` only.

    `device_id`, `transfer_port` and `manifest_port` travel outside the signed
    bytes, so a captured hello can be relabelled without invalidating the
    signature. These are expected failures until 1e binds the transcript.
    """

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "1e: the hello signature does not cover device_id/ports, so a "
            "captured hello can be relabelled and the responder will pin the "
            "identity key under the attacker-chosen id"
        ),
    )
    async def test_relabelled_device_id_is_rejected(self, tmp_path: Path) -> None:
        server = HandshakeServer(_responder("dev-b", tmp_path / "b"))
        await server.start("127.0.0.1", 19603)
        try:
            initiator = RawInitiator("dev-a", tmp_path / "a")
            wire = initiator.build_hello()
            (length,) = struct.unpack(_LENGTH_PREFIX, wire[:4])
            message = msgpack.unpackb(wire[4 : 4 + length], raw=False)
            message["device_id"] = "dev-evil"
            body = msgpack.packb(message)
            relabelled = struct.pack(_LENGTH_PREFIX, len(body)) + body

            await _exchange("127.0.0.1", 19603, relabelled)

            try:
                result = await asyncio.wait_for(server.results.get(), timeout=1)
            except TimeoutError:
                return  # the desired behaviour: the hello was refused
            raise AssertionError(
                f"responder accepted a relabelled hello and published a session "
                f"for {result.peer_device_id!r}"
            )
        finally:
            await server.stop()

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "1e: transfer_port/manifest_port are outside the signed transcript, "
            "so a captured hello can advertise attacker-chosen ports"
        ),
    )
    async def test_relabelled_ports_are_rejected(self, tmp_path: Path) -> None:
        server = HandshakeServer(_responder("dev-b", tmp_path / "b"))
        await server.start("127.0.0.1", 19604)
        try:
            initiator = RawInitiator("dev-a", tmp_path / "a")
            wire = initiator.build_hello()
            (length,) = struct.unpack(_LENGTH_PREFIX, wire[:4])
            message = msgpack.unpackb(wire[4 : 4 + length], raw=False)
            message["transfer_port"] = 1  # attacker-chosen
            body = msgpack.packb(message)
            relabelled = struct.pack(_LENGTH_PREFIX, len(body)) + body

            await _exchange("127.0.0.1", 19604, relabelled)
            try:
                result = await asyncio.wait_for(server.results.get(), timeout=1)
            except TimeoutError:
                return  # the desired behaviour: the hello was refused
            raise AssertionError(
                f"responder accepted a hello advertising transfer_port="
                f"{result.peer_transfer_port}"
            )
        finally:
            await server.stop()


def _restored(session: PeerSession) -> PeerSession:
    """A copy with a fresh window and counters at 1 (i.e. state loss)."""
    return PeerSession(
        peer_id=session.peer_id,
        session_id=session.session_id,
        role=session.role,
        send_key=session.send_key,
        receive_key=session.receive_key,
        transfer_port=session.transfer_port,
        manifest_port=session.manifest_port,
        confirmed=True,
        receive_window=AntiReplayWindow(),
    )
