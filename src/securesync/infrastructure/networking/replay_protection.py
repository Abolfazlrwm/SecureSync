"""Replay-protection primitives for the SecureSync wire protocol.

This module backs the v2 anti-replay / message-authenticity design
(Step 1d). It defines the *plaintext* wire frame header, the
associated-data (AAD) construction, the deterministic AEAD nonce, and
the timestamp-skew check. The sliding :class:`AntiReplayWindow` is
added in a sibling commit of the same step.

Design notes
------------
* The wire frame carries a **plaintext** header (version, direction,
  packet_type, session_id) *ahead* of the AEAD ciphertext. That lets
  the receiver (a) look the session up in O(1) by ``session_id`` and
  (b) build the AAD **before** decrypting — the AAD therefore never
  depends on bytes that only exist inside the ciphertext, which is the
  circular-dependency trap the earlier design fell into.
* ``direction`` is **role-based**, not "outbound/inbound":
  ``0x00`` = initiator→responder, ``0x01`` = responder→initiator. The
  receiver rejects any frame whose direction doesn't match the
  direction it expects for its own role, which also defeats
  reflection (A→B→A) attacks.
* The nonce is **deterministic** (direction + monotonically
  increasing counter + padding), so the receiver can recompute what
  the nonce *should* be from the plaintext direction and the inner
  header's ``message_id``, and reject any mismatch.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Final

from securesync.domain.crypto import NONCE_SIZE, TAG_SIZE, EncryptedPayload

# --- Frame / direction constants ------------------------------------------------

#: SecureSync wire-frame version. Bumped from 1→2 for the v2 anti-replay design;
#: this is the *frame* version, independent of the inner :class:`PacketHeader`.
FRAME_VERSION: Final = 2

#: A packet travelling from the handshake initiator to the responder.
DIRECTION_INITIATOR_TO_RESPONDER: Final = 0x00
#: A packet travelling from the handshake responder to the initiator.
DIRECTION_RESPONDER_TO_INITIATOR: Final = 0x01

#: This device opened the handshake (it is the connection initiator).
ROLE_INITIATOR: Final = 0x00
#: This device accepted the handshake (it is the connection responder).
ROLE_RESPONDER: Final = 0x01

SESSION_ID_SIZE: Final = 8
#: version(1) + direction(1) + packet_type(1) + session_id(8) == 11 bytes.
FRAME_HEADER_SIZE: Final = 11

#: Default allowed clock skew between peers, in milliseconds (5 minutes).
DEFAULT_TIMESTAMP_SKEW_MS: Final = 300_000


# --- Exceptions ----------------------------------------------------------------


class ReplayProtectionError(Exception):
    """Base class for all replay-protection failures."""


class FrameDecodeError(ReplayProtectionError):
    """The plaintext frame header could not be parsed."""


class NonceMismatchError(ReplayProtectionError):
    """The AEAD nonce did not match the recomputed expected nonce."""


class DirectionMismatchError(ReplayProtectionError):
    """The frame direction did not match what the receiver expected for its role."""


class PacketTypeMismatchError(ReplayProtectionError):
    """The plaintext frame packet_type did not match the inner header packet_type."""


class TimestampSkewError(ReplayProtectionError):
    """The packet timestamp was outside the allowed skew window."""


class UnsupportedVersionError(ReplayProtectionError):
    """The frame carried a wire-protocol version this build does not speak.

    Raised from the *plaintext* version byte, before any decryption, so a v1
    peer gets a clean, explicit error instead of an authentication failure.
    """


class AuthenticationError(ReplayProtectionError):
    """The AEAD tag did not verify (wrong key, tampered ciphertext or AAD)."""


class ReplayWindowRejectedError(ReplayProtectionError):
    """The frame's counter was rejected by the anti-replay window."""


class UnknownSessionError(ReplayProtectionError):
    """No session exists for the frame's ``session_id``."""


# --- Frame header pack / unpack ------------------------------------------------


def pack_frame_header(version: int, direction: int, packet_type: int, session_id: bytes) -> bytes:
    """Serialize the 11-byte plaintext frame header.

    Args:
        version: Wire-frame version (must equal :data:`FRAME_VERSION`).
        direction: One of the ``DIRECTION_*`` constants.
        packet_type: The :class:`~securesync.core.protocol.PacketType` value.
        session_id: Exactly :data:`SESSION_ID_SIZE` bytes.

    Returns:
        The 11-byte frame header.

    Raises:
        FrameDecodeError: If ``session_id`` is the wrong length.
    """
    if len(session_id) != SESSION_ID_SIZE:
        raise FrameDecodeError(f"session_id must be {SESSION_ID_SIZE} bytes, got {len(session_id)}")
    return struct.pack(">BBB8s", version & 0xFF, direction & 0xFF, packet_type & 0xFF, session_id)


def unpack_frame_header(data: bytes) -> tuple[int, int, int, bytes]:
    """Parse the 11-byte plaintext frame header from the front of ``data``.

    Args:
        data: At least :data:`FRAME_HEADER_SIZE` bytes (the frame header,
            usually followed by the AEAD envelope).

    Returns:
        ``(version, direction, packet_type, session_id)``.

    Raises:
        FrameDecodeError: If ``data`` is shorter than the header.
    """
    if len(data) < FRAME_HEADER_SIZE:
        raise FrameDecodeError(
            f"frame header must be >= {FRAME_HEADER_SIZE} bytes, got {len(data)}"
        )
    version, direction, packet_type, session_id = struct.unpack(">BBB8s", data[:FRAME_HEADER_SIZE])
    return version, direction, packet_type, session_id


# --- Complete frame encode / split --------------------------------------------

#: Minimum on-wire frame: header + nonce + tag (empty ciphertext).
MIN_FRAME_SIZE: Final = FRAME_HEADER_SIZE + NONCE_SIZE + TAG_SIZE


@dataclass(frozen=True, slots=True)
class FrameHeader:
    """The plaintext header of one wire frame.

    Attributes:
        version: Wire-frame version.
        direction: One of the ``DIRECTION_*`` constants.
        packet_type: The :class:`~securesync.core.protocol.PacketType` value.
        session_id: The 8-byte session identifier.
    """

    version: int
    direction: int
    packet_type: int
    session_id: bytes


def encode_frame(
    *,
    direction: int,
    packet_type: int,
    session_id: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    version: int = FRAME_VERSION,
) -> bytes:
    """Serialize a complete frame: header ‖ nonce ‖ ciphertext ‖ tag.

    Args:
        direction: One of the ``DIRECTION_*`` constants.
        packet_type: The packet type, also present in the AAD.
        session_id: Exactly :data:`SESSION_ID_SIZE` bytes.
        nonce: Exactly :data:`~securesync.domain.crypto.NONCE_SIZE` bytes.
        ciphertext: The AEAD ciphertext.
        tag: Exactly :data:`~securesync.domain.crypto.TAG_SIZE` bytes.
        version: Wire-frame version (defaults to :data:`FRAME_VERSION`).

    Returns:
        The complete frame bytes.

    Raises:
        FrameDecodeError: If any fixed-width field has the wrong length.
    """
    if len(nonce) != NONCE_SIZE:
        raise FrameDecodeError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
    if len(tag) != TAG_SIZE:
        raise FrameDecodeError(f"tag must be {TAG_SIZE} bytes, got {len(tag)}")
    return pack_frame_header(version, direction, packet_type, session_id) + nonce + ciphertext + tag


def split_frame(
    data: bytes,
) -> tuple[FrameHeader, bytes, EncryptedPayload]:
    """Parse a complete frame into its header, nonce and encrypted payload.

    Args:
        data: The frame bytes, as produced by :func:`encode_frame`.

    Returns:
        ``(header, nonce, payload)``.

    Raises:
        FrameDecodeError: If the frame is too short for its fixed-width fields.
    """
    if len(data) < MIN_FRAME_SIZE:
        raise FrameDecodeError(f"frame must be >= {MIN_FRAME_SIZE} bytes, got {len(data)}")
    version, direction, packet_type, session_id = unpack_frame_header(data)
    offset = FRAME_HEADER_SIZE
    nonce = data[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = data[offset : len(data) - TAG_SIZE]
    tag = data[len(data) - TAG_SIZE :]
    return (
        FrameHeader(
            version=version,
            direction=direction,
            packet_type=packet_type,
            session_id=session_id,
        ),
        nonce,
        EncryptedPayload(ciphertext=ciphertext, nonce=nonce, tag=tag),
    )


# --- Direction helpers ---------------------------------------------------------


def outgoing_direction(role: int) -> int:
    """The direction a packet travels when *sent* by a peer with ``role``.

    Args:
        role: One of the ``ROLE_*`` constants.

    Returns:
        The ``DIRECTION_*`` value for packets this peer sends.

    Raises:
        ReplayProtectionError: If ``role`` is unknown.
    """
    if role == ROLE_INITIATOR:
        return DIRECTION_INITIATOR_TO_RESPONDER
    if role == ROLE_RESPONDER:
        return DIRECTION_RESPONDER_TO_INITIATOR
    raise ReplayProtectionError(f"invalid role {role!r}")


def incoming_direction(role: int) -> int:
    """The direction a packet *must* have when *received* by a peer with ``role``.

    A responder expects initiator→responder traffic; an initiator expects
    responder→initiator traffic.

    Args:
        role: One of the ``ROLE_*`` constants.

    Returns:
        The expected ``DIRECTION_*`` value for inbound packets.

    Raises:
        ReplayProtectionError: If ``role`` is unknown.
    """
    peer_role = ROLE_RESPONDER if role == ROLE_INITIATOR else ROLE_INITIATOR
    return outgoing_direction(peer_role)


# --- Deterministic nonce -------------------------------------------------------


def derive_nonce(direction: int, counter: int) -> bytes:
    """Build the deterministic 12-byte AEAD nonce.

    Layout: ``direction(1) + counter(8) + zero-pad(3)``. Binding the
    direction into the nonce means a packet captured in one direction
    cannot be replayed in the other, and binding the counter means the
    receiver can recompute the expected nonce.

    Args:
        direction: One of the ``DIRECTION_*`` constants.
        counter: A monotonically increasing per-session counter (>= 1).

    Returns:
        The 12-byte nonce.

    Raises:
        ReplayProtectionError: If ``direction`` is invalid or ``counter`` <= 0.
    """
    if direction not in (DIRECTION_INITIATOR_TO_RESPONDER, DIRECTION_RESPONDER_TO_INITIATOR):
        raise ReplayProtectionError(f"invalid direction {direction!r}")
    if counter <= 0:
        raise ReplayProtectionError("counter must be >= 1")
    return struct.pack(">BQ", direction, counter) + b"\x00\x00\x00"


# --- Associated data (AAD) ----------------------------------------------------


def _length_prefixed(value: bytes) -> bytes:
    """Encode ``value`` as a 2-byte big-endian length followed by the bytes."""
    return struct.pack(">H", len(value)) + value


def build_aad(
    version: int,
    direction: int,
    packet_type: int,
    session_id: bytes,
    sender_id: bytes,
    receiver_id: bytes,
) -> bytes:
    """Construct the AEAD associated data for a frame.

    The AAD is built **before decryption** from the plaintext frame
    header plus the sender/receiver device IDs (which the receiver
    knows from session context). Every variable-length field is
    length-prefixed so two different ID/nonce splits can never
    produce the same AAD.

    Args:
        version: Wire-frame version.
        direction: One of the ``DIRECTION_*`` constants.
        packet_type: The frame's packet_type.
        session_id: Exactly :data:`SESSION_ID_SIZE` bytes (fixed-width,
            not length-prefixed).
        sender_id: The sender's device ID (bytes).
        receiver_id: The receiver's device ID (bytes).

    Returns:
        The AAD bytes to pass to the AEAD encrypt/decrypt calls.
    """
    return (
        struct.pack(">BBB", version & 0xFF, direction & 0xFF, packet_type & 0xFF)
        + session_id
        + _length_prefixed(sender_id)
        + _length_prefixed(receiver_id)
    )


# --- Timestamp skew -----------------------------------------------------------


def check_timestamp_skew(
    timestamp_ms: int,
    now_ms: int,
    max_skew_ms: int = DEFAULT_TIMESTAMP_SKEW_MS,
) -> bool:
    """Return whether ``timestamp_ms`` is within ``max_skew_ms`` of ``now_ms``.

    A pure check (no state mutation) — it may run after AEAD
    authentication but before the replay window is advanced.

    Args:
        timestamp_ms: The packet's claimed sender timestamp, in ms.
        now_ms: The receiver's current time, in ms.
        max_skew_ms: Maximum allowed absolute skew.

    Returns:
        ``True`` if the timestamp is within the skew window.
    """
    return abs(now_ms - timestamp_ms) <= max_skew_ms


def now_ms() -> int:
    """Return the current wall-clock time in milliseconds."""
    return int(time.time() * 1000)


# --- Replay window ------------------------------------------------------------

#: Default anti-replay window size (number of counters tracked around the
#: highest seen). RFC-4303 style: counters within this band of the highest
#: accepted counter are tolerated (out-of-order delivery), outside it they are
#: rejected as too-old or implausibly far in the future.
DEFAULT_REPLAY_WINDOW_SIZE: Final = 128


class AntiReplayWindow:
    """RFC-4303-style sliding replay window backed by a fixed-size bitmask.

    The window accepts counters in the band
    ``[highest - window + 1, highest + window]`` that have not already
    been seen. ``counter == 0`` is always rejected (a sender's counters
    start at 1).

    The bitmask has a fixed number of slots (``2 * window + 1``), so memory
    use is bounded regardless of how many packets flow; the window slides
    forward as the highest accepted counter grows, forgetting counters that
    fall off the low end.

    Design contract (Step 1d, amendment 2):

    * :meth:`would_accept` is a **pure** check — it never mutates state.
      The transport runs it *before* AEAD decryption, so a malformed or
      replayed packet cannot trigger any state change by reaching this far.
    * :meth:`accept` is the **only** mutating operation and is an atomic
      check-and-set: it returns ``False`` (and changes nothing) if the
      counter would be rejected, otherwise marks it and advances the window.
    * There is deliberately **no** ``revoke()``: a confirmed/accepted counter
      stays accepted forever (you cannot "un-accept" a packet), which is what
      makes replay impossible.
    """

    def __init__(self, window_size: int = DEFAULT_REPLAY_WINDOW_SIZE) -> None:
        """Initialize an empty window.

        Args:
            window_size: Number of counters tracked on either side of the
                highest seen. Must be positive.

        Raises:
            ReplayProtectionError: If ``window_size`` is not positive.
        """
        if window_size <= 0:
            raise ReplayProtectionError("window_size must be positive")
        self._window = window_size
        self._slots = 2 * window_size + 1
        self._bits: bytearray = bytearray((self._slots + 7) // 8)
        self._highest = 0
        # Invariant: _base == _highest - _window + 1. The lowest counter still
        # representable in the bitmask.
        self._base = 1 - window_size

    @property
    def highest_accepted(self) -> int:
        """The highest counter this window has ever accepted (0 = none)."""
        return self._highest

    def _slot(self, counter: int) -> int:
        return counter - self._base

    def _is_set(self, slot: int) -> bool:
        return bool(self._bits[slot >> 3] & (1 << (slot & 7)))

    def _set(self, slot: int) -> None:
        self._bits[slot >> 3] |= 1 << (slot & 7)

    def would_accept(self, counter: int) -> bool:
        """Pure check: would ``accept(counter)`` succeed right now?

        Never mutates state. Rejects ``counter <= 0``, counters more than
        ``window`` above the highest seen, counters older than the lowest
        still remembered, and already-seen counters.
        """
        if counter <= 0:
            return False
        if counter > self._highest + self._window:
            return False
        if counter < self._highest - self._window + 1:
            return False
        slot = self._slot(counter)
        if slot < 0 or slot >= self._slots:
            return False
        return not self._is_set(slot)

    def accept(self, counter: int) -> bool:
        """Atomically accept ``counter`` if :meth:`would_accept` is true.

        Returns:
            ``True`` if the counter was newly accepted, ``False`` if it was
            rejected (duplicate, too old, too new, or ``<= 0``). The only
            state change happens on ``True``.
        """
        if not self.would_accept(counter):
            return False
        if counter > self._highest:
            self._slide(counter - self._window + 1)
            self._highest = counter
        self._set(self._slot(counter))
        return True

    def _slide(self, new_base: int) -> None:
        """Slide the window forward so its low end becomes ``new_base``.

        Right-shifts the bitmask by ``new_base - _base`` slots: a bit for
        counter ``v`` moves from slot ``v - old_base`` to ``v - new_base``.
        Counters that fall below ``new_base`` are dropped (forgotten, because
        they are now outside the window's lower bound), and the vacated high
        slots are cleared.
        """
        delta = new_base - self._base
        if delta <= 0:
            self._base = new_base
            return
        old = self._bits
        new = bytearray(len(old))
        total = self._slots
        for i in range(total):
            if (old[i >> 3] >> (i & 7)) & 1:
                j = i - delta
                if 0 <= j < total:
                    new[j >> 3] |= 1 << (j & 7)
        self._bits = new
        self._base = new_base
