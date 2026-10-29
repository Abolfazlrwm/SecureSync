"""Unit tests for the replay-protection primitives (frame, AAD, nonce, skew)."""

from __future__ import annotations

import pytest

from securesync.infrastructure.networking.replay_protection import (
    DIRECTION_INITIATOR_TO_RESPONDER,
    DIRECTION_RESPONDER_TO_INITIATOR,
    FRAME_HEADER_SIZE,
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    SESSION_ID_SIZE,
    AntiReplayWindow,
    FrameDecodeError,
    ReplayProtectionError,
    build_aad,
    check_timestamp_skew,
    derive_nonce,
    incoming_direction,
    outgoing_direction,
    pack_frame_header,
    unpack_frame_header,
)

SESSION_ID = b"\x01\x02\x03\x04\x05\x06\x07\x08"


class TestFrameHeader:
    def test_pack_unpack_round_trips(self) -> None:
        header = pack_frame_header(2, DIRECTION_INITIATOR_TO_RESPONDER, 0x12, SESSION_ID)
        assert len(header) == FRAME_HEADER_SIZE
        version, direction, packet_type, session_id = unpack_frame_header(header)
        assert version == 2
        assert direction == DIRECTION_INITIATOR_TO_RESPONDER
        assert packet_type == 0x12
        assert session_id == SESSION_ID

    def test_rejects_wrong_length_session_id(self) -> None:
        with pytest.raises(FrameDecodeError):
            pack_frame_header(2, 0, 0, b"abc")

    def test_rejects_short_input_on_unpack(self) -> None:
        with pytest.raises(FrameDecodeError):
            unpack_frame_header(b"\x00\x01\x02")


class TestDirectionHelpers:
    def test_outgoing_initiator_is_i2r(self) -> None:
        assert outgoing_direction(ROLE_INITIATOR) == DIRECTION_INITIATOR_TO_RESPONDER

    def test_outgoing_responder_is_r2i(self) -> None:
        assert outgoing_direction(ROLE_RESPONDER) == DIRECTION_RESPONDER_TO_INITIATOR

    def test_incoming_responder_expects_i2r(self) -> None:
        assert incoming_direction(ROLE_RESPONDER) == DIRECTION_INITIATOR_TO_RESPONDER

    def test_incoming_initiator_expects_r2i(self) -> None:
        assert incoming_direction(ROLE_INITIATOR) == DIRECTION_RESPONDER_TO_INITIATOR

    def test_invalid_role_raises(self) -> None:
        with pytest.raises(ReplayProtectionError):
            outgoing_direction(0x99)


class TestDeriveNonce:
    def test_layout_is_direction_counter_padding(self) -> None:
        nonce = derive_nonce(DIRECTION_INITIATOR_TO_RESPONDER, 1)
        assert len(nonce) == 12
        assert nonce[0] == DIRECTION_INITIATOR_TO_RESPONDER
        # 8-byte big-endian counter == 1, then 3 zero padding bytes.
        assert nonce[1:9] == (1).to_bytes(8, "big")
        assert nonce[9:] == b"\x00\x00\x00"

    def test_counter_is_reflected_in_nonce(self) -> None:
        n1 = derive_nonce(DIRECTION_RESPONDER_TO_INITIATOR, 42)
        n2 = derive_nonce(DIRECTION_RESPONDER_TO_INITIATOR, 43)
        assert n1 != n2
        assert n1[1:9] == (42).to_bytes(8, "big")

    def test_rejects_counter_zero(self) -> None:
        with pytest.raises(ReplayProtectionError):
            derive_nonce(DIRECTION_INITIATOR_TO_RESPONDER, 0)

    def test_rejects_invalid_direction(self) -> None:
        with pytest.raises(ReplayProtectionError):
            derive_nonce(0x55, 1)


class TestBuildAad:
    def test_aad_is_deterministic_and_distinct(self) -> None:
        a = build_aad(2, 0, 0x12, SESSION_ID, b"sender", b"receiver")
        b = build_aad(2, 0, 0x12, SESSION_ID, b"sender", b"receiver")
        assert a == b

    def test_swapped_ids_produce_different_aad(self) -> None:
        a = build_aad(2, 0, 0x12, SESSION_ID, b"sender", b"receiver")
        b = build_aad(2, 0, 0x12, SESSION_ID, b"receiver", b"sender")
        assert a != b

    def test_length_prefixing_prevents_id_split_collision(self) -> None:
        # "ab"+"cd" vs "abc"+"d" must NOT collide under length-prefixing.
        a = build_aad(2, 0, 0x12, SESSION_ID, b"ab", b"cd")
        b = build_aad(2, 0, 0x12, SESSION_ID, b"abc", b"d")
        assert a != b

    def test_different_session_id_produces_different_aad(self) -> None:
        other = b"\xff" * SESSION_ID_SIZE
        a = build_aad(2, 0, 0x12, SESSION_ID, b"s", b"r")
        b = build_aad(2, 0, 0x12, other, b"s", b"r")
        assert a != b


class TestTimestampSkew:
    def test_within_skew_passes(self) -> None:
        assert check_timestamp_skew(1000, 1000 + 100, max_skew_ms=300_000)
        assert check_timestamp_skew(1000, 1000 + 300_000, max_skew_ms=300_000)

    def test_outside_skew_fails(self) -> None:
        assert not check_timestamp_skew(1000, 1000 + 300_001, max_skew_ms=300_000)
        assert not check_timestamp_skew(1000, 1000 - 300_001, max_skew_ms=300_000)


class TestAntiReplayWindow:
    def test_first_counter_accepted_then_duplicate_rejected(self) -> None:
        w = AntiReplayWindow(8)
        assert w.accept(1) is True
        assert w.accept(1) is False  # duplicate

    def test_counter_zero_is_always_rejected(self) -> None:
        w = AntiReplayWindow(8)
        assert w.would_accept(0) is False
        assert w.accept(0) is False

    def test_would_accept_is_pure(self) -> None:
        w = AntiReplayWindow(8)
        # Calling would_accept does not mutate: a far-but-in-window counter
        # is still accepted afterwards and highest is still 0.
        assert w.would_accept(5) is True
        assert w.would_accept(5) is True
        assert w.highest_accepted == 0
        assert w.accept(5) is True
        assert w.highest_accepted == 5

    def test_out_of_order_within_window(self) -> None:
        w = AntiReplayWindow(8)
        assert w.accept(1) is True
        assert w.accept(3) is True  # out of order, still within window
        assert w.accept(2) is True  # fills the gap
        assert w.accept(3) is False  # duplicate
        assert w.accept(9) is True  # within highest(3) + window(8)
        assert w.accept(11) is True  # advances the highest accepted counter
        # 2 is now below the window's lower bound and must be rejected.
        assert w.accept(2) is False  # too old (fell below the window)

    def test_too_old_counter_rejected_after_slide(self) -> None:
        w = AntiReplayWindow(2)
        assert w.accept(1) is True
        assert w.accept(3) is True
        # 1 is now older than highest(3) - window(2) + 1 == 2
        assert w.would_accept(1) is False
        assert w.accept(1) is False

    def test_far_future_counter_does_not_advance_window(self) -> None:
        w = AntiReplayWindow(8)
        # A counter far beyond highest + window is rejected as too-new and
        # must NOT advance the window (otherwise an attacker could shift it).
        assert w.would_accept(10_000) is False
        assert w.accept(10_000) is False
        assert w.highest_accepted == 0

    def test_concurrent_identical_packets_accepted_exactly_once(self) -> None:
        w = AntiReplayWindow(8)
        assert w.accept(5) is True
        # Two copies of the same counter arriving "at once" — only one wins.
        assert w.accept(5) is False
        assert w.accept(5) is False

    def test_invalid_window_size_rejected(self) -> None:
        with pytest.raises(ReplayProtectionError):
            AntiReplayWindow(0)
