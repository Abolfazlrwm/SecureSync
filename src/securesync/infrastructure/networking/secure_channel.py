"""Sealing and opening v2 wire frames for one device.

This is the single implementation of the receive order in the Step 1d design,
so both TCP transports share exactly the same checks:

1. cheap, non-mutating pre-filters — frame version, session lookup by
   ``session_id``, expected direction for our role, and
   :meth:`AntiReplayWindow.would_accept` on the counter carried in the nonce;
2. AEAD decrypt/authenticate with the AAD from the design;
3. the nonce must equal ``derive_nonce(direction, header.message_id)``;
4. the inner ``packet_type`` must equal the plaintext one;
5. timestamp skew (pure check, secondary defence);
6. :meth:`AntiReplayWindow.accept` **last** — the only state mutation, only
   after the frame authenticated and every other check passed;
7. confirm a responder-side session and record activity.

Nothing before step 6 mutates replay state, so an attacker who forges a frame
with a huge counter cannot lock the legitimate sender out.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from securesync.core.protocol import Packet, PacketType, make_header
from securesync.domain.crypto import AeadCipher
from securesync.infrastructure.networking.replay_protection import (
    DEFAULT_TIMESTAMP_SKEW_MS,
    FRAME_VERSION,
    ROLE_RESPONDER,
    AuthenticationError,
    DirectionMismatchError,
    NonceMismatchError,
    PacketTypeMismatchError,
    ReplayWindowRejectedError,
    TimestampSkewError,
    UnknownSessionError,
    UnsupportedVersionError,
    build_aad,
    check_timestamp_skew,
    derive_nonce,
    encode_frame,
    incoming_direction,
    now_ms,
    outgoing_direction,
    split_frame,
)
from securesync.infrastructure.networking.session_store import PeerSession, SessionStore


class SecureChannel:
    """Seals outbound packets and opens inbound frames for one device."""

    def __init__(
        self,
        own_device_id: str,
        cipher: AeadCipher,
        sessions: SessionStore,
        *,
        timestamp_skew_ms: int = DEFAULT_TIMESTAMP_SKEW_MS,
        clock_ms: Callable[[], int] = now_ms,
    ) -> None:
        """Initialize the channel.

        Args:
            own_device_id: This device's ID, used as the AAD receiver at
                receive time and the AAD sender at send time.
            cipher: The AEAD cipher.
            sessions: The session store holding negotiated keys.
            timestamp_skew_ms: Maximum accepted clock skew, in milliseconds.
            clock_ms: Wall clock in milliseconds, injectable for tests.
        """
        self._own_device_id = own_device_id
        self._cipher = cipher
        self._sessions = sessions
        self._timestamp_skew_ms = timestamp_skew_ms
        self._clock_ms = clock_ms

    @property
    def sessions(self) -> SessionStore:
        """The session store this channel reads and confirms through."""
        return self._sessions

    def seal(self, session: PeerSession, packet_type: PacketType, payload: dict[str, Any]) -> bytes:
        """Encrypt ``payload`` into a complete wire frame.

        The AEAD counter is taken from the session and used as both the nonce
        counter and the inner header's ``message_id``, so the receiver can
        recompute the expected nonce.

        Args:
            session: The session to send under. Must be confirmed.
            packet_type: The packet type (plaintext, and bound by the AAD).
            payload: The packet payload.

        Returns:
            The frame bytes, ready to be length-prefixed onto the wire.

        Raises:
            CounterExhaustedError: If the session's key is used up; the caller
                must open a new session.
        """
        counter = session.allocate_counter()
        header = make_header(packet_type, message_id=counter)
        framed = Packet(header=header, payload=payload).encode()

        direction = outgoing_direction(session.role)
        nonce = derive_nonce(direction, counter)
        aad = build_aad(
            FRAME_VERSION,
            direction,
            int(packet_type),
            session.session_id,
            self._own_device_id.encode("utf-8"),
            session.peer_id.encode("utf-8"),
        )
        encrypted = self._cipher.encrypt(framed, session.send_key, nonce, associated_data=aad)
        session.mark_active()
        return encode_frame(
            direction=direction,
            packet_type=int(packet_type),
            session_id=session.session_id,
            nonce=nonce,
            ciphertext=encrypted.ciphertext,
            tag=encrypted.tag,
        )

    def open(self, frame: bytes) -> tuple[Packet, PeerSession]:
        """Authenticate, decrypt and replay-check one inbound frame.

        Args:
            frame: The complete frame bytes (after the length prefix).

        Returns:
            The decoded packet and the session it was authenticated under.

        Raises:
            UnsupportedVersionError: The frame version is not
                :data:`FRAME_VERSION` (e.g. a v1 peer).
            UnknownSessionError: No session matches the frame's ``session_id``.
            DirectionMismatchError: The frame direction is wrong for our role
                (this is what rejects a reflected frame).
            ReplayWindowRejectedError: The counter is a duplicate or too old.
            AuthenticationError: The AEAD tag did not verify.
            NonceMismatchError: The nonce does not match the inner message id.
            PacketTypeMismatchError: Inner and outer packet types disagree.
            TimestampSkewError: The packet timestamp is outside the skew window.
        """
        header, nonce, encrypted = split_frame(frame)

        # (a) cheap pre-filters, no state mutation.
        if header.version != FRAME_VERSION:
            raise UnsupportedVersionError(
                f"unsupported frame version {header.version} (this build speaks "
                f"v{FRAME_VERSION})"
            )
        session = self._sessions.get_by_session_id(header.session_id)
        if session is None:
            raise UnknownSessionError(
                f"no session for {header.session_id.hex()} — handshake required"
            )
        if header.direction != incoming_direction(session.role):
            raise DirectionMismatchError(
                f"direction {header.direction} not expected for role {session.role}"
            )
        counter = int.from_bytes(nonce[1:9], "big")
        if not session.receive_window.would_accept(counter):
            raise ReplayWindowRejectedError(f"counter {counter} rejected before authentication")

        # (b) authenticate and decrypt. The AAD takes the sender identity from
        # the authenticated session, never from the packet.
        aad = build_aad(
            header.version,
            header.direction,
            header.packet_type,
            header.session_id,
            session.peer_id.encode("utf-8"),
            self._own_device_id.encode("utf-8"),
        )
        try:
            framed = self._cipher.decrypt(encrypted, session.receive_key, associated_data=aad)
        except Exception as exc:  # cryptography raises InvalidTag
            raise AuthenticationError("frame failed AEAD authentication") from exc

        packet = Packet.decode(framed)

        # (c) the nonce must be exactly what the header implies.
        expected_nonce = derive_nonce(header.direction, packet.header.message_id)
        if nonce != expected_nonce:
            raise NonceMismatchError(f"nonce does not match message_id {packet.header.message_id}")
        # (d) inner and outer packet types must agree.
        if int(packet.header.packet_type) != header.packet_type:
            raise PacketTypeMismatchError(
                f"inner packet_type {int(packet.header.packet_type)} != "
                f"outer {header.packet_type}"
            )
        # (e) timestamp skew — pure, secondary defence only.
        skew = abs(self._clock_ms() - packet.header.timestamp)
        if not check_timestamp_skew(
            packet.header.timestamp, self._clock_ms(), self._timestamp_skew_ms
        ):
            raise TimestampSkewError(
                f"timestamp skew {skew}ms exceeds limit {self._timestamp_skew_ms}ms"
            )
        # (f) the only state mutation, last.
        if not session.receive_window.accept(counter):
            raise ReplayWindowRejectedError(f"counter {counter} already accepted")
        # (g) confirmation and activity.
        if session.role == ROLE_RESPONDER:
            session.confirmed = True
        session.mark_active()
        return packet, session
