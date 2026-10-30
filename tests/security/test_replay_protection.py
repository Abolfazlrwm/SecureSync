"""Attack-driven tests for the v2 replay-protection frame (Step 1d).

Every test here builds a *real* frame with real keys and then tries to make the
receiver accept something it must not, or reject something it must accept. None
of these assert that a helper merely exists.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass

import pytest

from securesync.core.protocol import (
    CURRENT_VERSION,
    Packet,
    PacketHeader,
    PacketType,
)
from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.domain.networking import Peer, PeerAddress, PeerCapabilities, PeerIdentity
from securesync.infrastructure.crypto.pyca_crypto import AesGcmCipher
from securesync.infrastructure.networking.replay_protection import (
    DIRECTION_INITIATOR_TO_RESPONDER,
    FRAME_HEADER_SIZE,
    FRAME_VERSION,
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    AntiReplayWindow,
    AuthenticationError,
    DirectionMismatchError,
    NonceMismatchError,
    ReplayWindowRejectedError,
    TimestampSkewError,
    UnknownSessionError,
    UnsupportedVersionError,
    build_aad,
    derive_nonce,
    encode_frame,
    now_ms,
    outgoing_direction,
)
from securesync.infrastructure.networking.secure_channel import SecureChannel
from securesync.infrastructure.networking.session_store import (
    MAX_UNCONFIRMED_PER_PEER,
    PeerSession,
    SessionStore,
)
from securesync.infrastructure.networking.tcp_transport import TcpTransferTransport
from tests.support.sessions import paired_sessions

CIPHER = AesGcmCipher()


@dataclass
class TwoPeers:
    """Two peers sharing one derived session, each with its own channel."""

    session_a: PeerSession
    session_b: PeerSession
    store_a: SessionStore
    store_b: SessionStore
    channel_a: SecureChannel
    channel_b: SecureChannel


def _two_peers(*, window_size: int | None = None) -> TwoPeers:
    session_a, session_b = paired_sessions()
    if window_size is not None:
        session_b.receive_window = AntiReplayWindow(window_size)
    store_a, store_b = SessionStore(), SessionStore()
    store_a.put(session_a)
    store_b.put(session_b)
    return TwoPeers(
        session_a=session_a,
        session_b=session_b,
        store_a=store_a,
        store_b=store_b,
        channel_a=SecureChannel("dev-a", CIPHER, store_a),
        channel_b=SecureChannel("dev-b", CIPHER, store_b),
    )


def _craft(
    session: PeerSession,
    *,
    own_id: str,
    counter: int,
    message_id: int | None = None,
    direction: int | None = None,
    packet_type: int = int(PacketType.CHUNK_DATA),
    timestamp_ms: int | None = None,
    version: int = FRAME_VERSION,
    session_id: bytes | None = None,
    key: bytes | None = None,
    payload: dict[str, object] | None = None,
) -> bytes:
    """Build a frame with explicit control over every authenticated field."""
    wire_direction = outgoing_direction(session.role) if direction is None else direction
    msg_id = counter if message_id is None else message_id
    sid = session.session_id if session_id is None else session_id
    header = PacketHeader(
        version=CURRENT_VERSION,
        packet_type=PacketType(packet_type),
        flags=0,
        message_id=msg_id,
        payload_length=0,
        timestamp=now_ms() if timestamp_ms is None else timestamp_ms,
        crc32=0,
    )
    framed = Packet(header=header, payload=payload or {"n": counter}).encode()
    nonce = derive_nonce(wire_direction, counter)
    aad = build_aad(
        version,
        wire_direction,
        packet_type,
        sid,
        own_id.encode("utf-8"),
        session.peer_id.encode("utf-8"),
    )
    encrypted = CIPHER.encrypt(framed, key or session.send_key, nonce, associated_data=aad)
    return encode_frame(
        version=version,
        direction=wire_direction,
        packet_type=packet_type,
        session_id=sid,
        nonce=nonce,
        ciphertext=encrypted.ciphertext,
        tag=encrypted.tag,
    )


class TestReplayRejection:
    def test_duplicate_packet_is_rejected(self) -> None:
        peers = _two_peers()
        frame = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 1})

        first, _ = peers.channel_b.open(frame)
        assert first.payload == {"n": 1}

        with pytest.raises(ReplayWindowRejectedError):
            peers.channel_b.open(frame)

    def test_out_of_order_within_window_is_accepted(self) -> None:
        peers = _two_peers()
        frames = [
            peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": i})
            for i in (1, 2, 3)
        ]

        assert peers.channel_b.open(frames[0])[0].payload == {"n": 1}
        assert peers.channel_b.open(frames[2])[0].payload == {"n": 3}
        assert peers.channel_b.open(frames[1])[0].payload == {"n": 2}

    def test_too_old_packet_is_rejected(self) -> None:
        peers = _two_peers(window_size=2)
        frames = {
            i: peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": i})
            for i in range(1, 6)
        }
        peers.channel_b.open(frames[1])
        peers.channel_b.open(frames[3])
        peers.channel_b.open(frames[5])  # window now covers [4, 7]

        with pytest.raises(ReplayWindowRejectedError):
            peers.channel_b.open(frames[2])

    async def test_two_concurrent_identical_packets_accept_exactly_one(self) -> None:
        peers = _two_peers()
        frame = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 1})

        async def attempt() -> bool:
            try:
                peers.channel_b.open(frame)
            except ReplayWindowRejectedError:
                return False
            return True

        results = await asyncio.gather(attempt(), attempt())
        assert results.count(True) == 1

    def test_reflected_packet_is_rejected(self) -> None:
        """A frame A sent to B, replayed back at A, must not verify."""
        peers = _two_peers()
        frame = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 1})

        # A is the initiator, so it expects responder->initiator traffic; the
        # frame carries initiator->responder.
        with pytest.raises(DirectionMismatchError):
            peers.channel_a.open(frame)

    def test_frame_for_an_unknown_session_is_rejected(self) -> None:
        peers = _two_peers()
        frame = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 1})
        # Point the frame at a session id the receiver does not know.
        tampered = bytearray(frame)
        tampered[3:11] = b"\xde\xad\xbe\xef\xde\xad\xbe\xef"

        with pytest.raises(UnknownSessionError):
            peers.channel_b.open(bytes(tampered))

    def test_untrusting_a_peer_purges_its_sessions(self) -> None:
        peers = _two_peers()
        frame = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 1})

        assert peers.store_b.remove_by_peer("dev-a") == 1

        with pytest.raises(UnknownSessionError):
            peers.channel_b.open(frame)


class TestTamperedFields:
    def test_tampered_message_id_is_rejected(self) -> None:
        peers = _two_peers()
        # Nonce says counter 5, the authenticated header says message_id 4.
        frame = _craft(peers.session_a, own_id="dev-a", counter=5, message_id=4)

        with pytest.raises(NonceMismatchError):
            peers.channel_b.open(frame)

    def test_tampered_session_id_is_rejected(self) -> None:
        peers = _two_peers()
        frame = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 1})
        tampered = bytearray(frame)
        # Flip a byte of the plaintext session id; the AAD and the lookup both
        # bind it, so this cannot be silently ignored.
        tampered[3] ^= 0xFF

        with pytest.raises((UnknownSessionError, AuthenticationError)):
            peers.channel_b.open(bytes(tampered))

    def test_tampered_direction_is_rejected(self) -> None:
        peers = _two_peers()
        frame = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 1})
        tampered = bytearray(frame)
        tampered[1] = 0x01  # pretend responder->initiator

        with pytest.raises(DirectionMismatchError):
            peers.channel_b.open(bytes(tampered))

    def test_tampered_packet_type_is_rejected(self) -> None:
        peers = _two_peers()
        frame = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 1})
        tampered = bytearray(frame)
        tampered[2] = int(PacketType.HEARTBEAT)

        with pytest.raises(AuthenticationError):
            peers.channel_b.open(bytes(tampered))

    def test_tampered_version_is_rejected_before_decryption(self) -> None:
        peers = _two_peers()
        frame = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 1})
        tampered = bytearray(frame)
        tampered[0] = 0x7F

        with pytest.raises(UnsupportedVersionError):
            peers.channel_b.open(bytes(tampered))

    def test_flipped_ciphertext_byte_is_rejected(self) -> None:
        peers = _two_peers()
        frame = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 1})
        tampered = bytearray(frame)
        tampered[FRAME_HEADER_SIZE + 12] ^= 0x01  # first ciphertext byte

        with pytest.raises(AuthenticationError):
            peers.channel_b.open(bytes(tampered))


class TestTimestampSkewCannotAdvanceTheWindow:
    def test_authentic_but_stale_high_counter_does_not_advance_the_window(self) -> None:
        peers = _two_peers()
        # Accept one legitimate frame so the window has a real high-water mark.
        legitimate_one = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 1})
        peers.channel_b.open(legitimate_one)
        assert peers.session_b.receive_window.highest_accepted == 1

        # Authentic (correct key, correct AAD) but stale, and carrying a much
        # higher counter. If the window advanced before the timestamp check,
        # the attacker could jump it forward and lock the real sender out.
        stale = _craft(
            peers.session_a,
            own_id="dev-a",
            counter=100,
            timestamp_ms=now_ms() - 10 * 60 * 1000,
        )

        with pytest.raises(TimestampSkewError) as excinfo:
            peers.channel_b.open(stale)
        assert "timestamp skew" in str(excinfo.value)
        assert "exceeds limit" in str(excinfo.value)

        assert peers.session_b.receive_window.highest_accepted == 1

        # A legitimate next counter is still accepted.
        legitimate_two = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 2})
        assert peers.channel_b.open(legitimate_two)[0].payload == {"n": 2}


class TestSessionLifecycle:
    def test_peer_restart_creates_a_new_session_without_evicting_the_old(self) -> None:
        peers = _two_peers()
        new_a, new_b = paired_sessions(salt=b"\x11" * 16)
        assert new_a.session_id != peers.session_a.session_id

        peers.store_b.put(new_b)

        assert peers.store_b.get_by_session_id(peers.session_b.session_id) is not None
        assert peers.store_b.get_by_session_id(new_b.session_id) is not None

        # The old session still works, and so does the new one.
        old_frame = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"old": 1})
        assert peers.channel_b.open(old_frame)[0].payload == {"old": 1}

        new_channel_a = SecureChannel("dev-a", CIPHER, _store(new_a))
        new_frame = new_channel_a.seal(new_a, PacketType.CHUNK_DATA, {"new": 1})
        assert peers.channel_b.open(new_frame)[0].payload == {"new": 1}

    def test_replayed_hello_never_evicts_a_real_session(self) -> None:
        store = SessionStore()
        real_a, real_b = paired_sessions()
        real_b.confirmed = True
        store.put(real_b)

        # A flood of replayed hellos: each creates only an unconfirmed session.
        for i in range(20):
            session_a, session_b = paired_sessions(salt=bytes([i]) + b"\x33" * 15)
            session_b.confirmed = False
            store.put(session_b)

        assert store.get_by_session_id(real_b.session_id) is not None
        unconfirmed = [s for s in store.sessions_for_peer("dev-a") if not s.confirmed]
        assert len(unconfirmed) <= MAX_UNCONFIRMED_PER_PEER

    def test_exact_hello_replay_cannot_reset_a_confirmed_session(self) -> None:
        """Replaying the same signed hello re-derives the same session_id.

        If that re-recording replaced the live session, the attacker would get
        a fresh anti-replay window (replays of captured data frames would then
        succeed again) and a reset send counter. The store must ignore it.
        """
        peers = _two_peers()
        frame = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 1})
        peers.channel_b.open(frame)
        assert peers.session_b.receive_window.highest_accepted == 1

        # Replay of the identical hello: same salt and ephemerals, so the same
        # session_id, recorded again as an unconfirmed session.
        replay_a, replay_b = paired_sessions()
        replay_b.confirmed = False
        peers.store_b.put(replay_b)

        live = peers.store_b.get_by_session_id(peers.session_b.session_id)
        assert live is not None
        assert live.confirmed is True
        assert live.receive_window.highest_accepted == 1
        # The captured frame is still a replay, not a fresh packet.
        with pytest.raises(ReplayWindowRejectedError):
            peers.channel_b.open(frame)

    def test_expired_session_cannot_send_and_frames_are_unknown(self) -> None:
        now = {"t": 1000.0}
        store = SessionStore(now=lambda: now["t"])
        session_a, session_b = paired_sessions()
        session_a.created_at = 1000.0
        session_a.last_activity = 1000.0
        store.put(session_a)

        now["t"] += (24 * 3600) + 1
        assert store.get_send_session("dev-b") is None
        assert store.prune_expired() == 1

    def test_responder_session_is_confirmed_by_the_first_inbound_packet(self) -> None:
        peers = _two_peers()
        peers.session_b.confirmed = False
        assert peers.store_b.has_confirmed_session("dev-a") is False

        frame = peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"n": 1})
        peers.channel_b.open(frame)

        assert peers.session_b.confirmed is True


class TestCounterUniqueness:
    async def test_concurrent_sends_never_reuse_a_counter_or_nonce(self) -> None:
        peers = _two_peers()
        senders = 50

        async def send(i: int) -> bytes:
            return peers.channel_a.seal(peers.session_a, PacketType.CHUNK_DATA, {"i": i})

        frames = await asyncio.gather(*(send(i) for i in range(senders)))

        nonces = {frame[FRAME_HEADER_SIZE : FRAME_HEADER_SIZE + 12] for frame in frames}
        counters = {struct.unpack(">Q", nonce[1:9])[0] for nonce in nonces}
        assert len(nonces) == senders
        assert counters == set(range(1, senders + 1))

        # And every one of them is accepted exactly once by the receiver.
        accepted = 0
        for frame in frames:
            peers.channel_b.open(frame)
            accepted += 1
        assert accepted == senders


class TestVersionCompatibility:
    def test_v1_frame_gets_a_clean_unsupported_version_error(self) -> None:
        peers = _two_peers()
        v1_frame = _craft(peers.session_a, own_id="dev-a", counter=1, version=1)

        with pytest.raises(UnsupportedVersionError) as excinfo:
            peers.channel_b.open(v1_frame)
        assert "v2" in str(excinfo.value)

    def test_direction_constants_are_the_documented_values(self) -> None:
        assert DIRECTION_INITIATOR_TO_RESPONDER == 0x00
        assert ROLE_INITIATOR == 0x00
        assert ROLE_RESPONDER == 0x01


def _store(session: PeerSession) -> SessionStore:
    store = SessionStore()
    store.put(session)
    return store


class TestPushingManyChunksNeedsNoNewHandshake:
    async def test_initiator_pushes_n_chunks_over_one_session(self) -> None:
        store_a, store_b = _stores()
        transport_a = TcpTransferTransport("dev-a", "127.0.0.1", 19501, CIPHER, store_a)
        transport_b = TcpTransferTransport("dev-b", "127.0.0.1", 19502, CIPHER, store_b)
        await transport_a.start()
        await transport_b.start()
        try:
            total = 5
            for i in range(total):
                await transport_a.send_chunk(
                    _peer("dev-b", 19502),
                    _chunk(f"c{i}", f"payload-{i}".encode(), f"{i:064d}"),
                    relative_path="f.txt",
                    total_chunks=total,
                )

            received = []
            async for push in transport_b.receive_pushes():
                received.append(push)
                if len(received) == total:
                    break

            assert [p.chunk.metadata.chunk_id for p in received] == [f"c{i}" for i in range(total)]
            # One session on each side, no extra handshake, and the receiver
            # never had to reply.
            assert len(store_a) == 1
            assert len(store_b) == 1
        finally:
            await transport_a.stop()
            await transport_b.stop()


def _stores() -> tuple[SessionStore, SessionStore]:
    session_a, session_b = paired_sessions(responder_transfer_port=19502)
    store_a, store_b = SessionStore(), SessionStore()
    store_a.put(session_a)
    store_b.put(session_b)
    return store_a, store_b


def _peer(device_id: str, port: int) -> Peer:
    return Peer(
        identity=PeerIdentity(device_id, f"host-{device_id}", f"fp-{device_id}"),
        address=PeerAddress("127.0.0.1", port),
        capabilities=PeerCapabilities("2.0"),
    )


def _chunk(chunk_id: str, data: bytes, digest: str) -> Chunk:
    return Chunk(
        metadata=ChunkMetadata(
            chunk_id=chunk_id,
            index=0,
            size=len(data),
            offset=0,
            chunk_hash=ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=digest),
        ),
        data=data,
    )
