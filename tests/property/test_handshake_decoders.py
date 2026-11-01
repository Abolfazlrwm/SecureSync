"""Property-based tests for the v3 handshake decoders.

The decoders are the only place untrusted bytes become structured data, so the
invariants checked here are the ones a malicious peer would attack:

* **No crash.** For arbitrary bytes, a decoder either returns a message or
  raises one of the typed handshake errors. Anything else — ``IndexError``,
  ``struct.error``, ``UnicodeDecodeError``, ``ValueError`` — would mean a peer
  can choose which exception the process sees.
* **No unbounded allocation.** A declared length is validated *before* it is
  used to slice the buffer, so a 2-byte prefix cannot make the receiver read or
  allocate 64 KiB.
* **Round-trip stability.** ``decode(encode(m))`` reproduces every field, and
  re-encoding gives the same bytes, so the transcript a peer hashes is the
  transcript we hashed.
* **Strictness.** Trailing bytes, a wrong version and a wrong ``msg_type`` are
  always rejected rather than ignored.
"""

from __future__ import annotations

import struct
from collections.abc import Callable

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from securesync.infrastructure.networking.handshake_messages import (
    HANDSHAKE_VERSION,
    MAX_DEVICE_ID_BYTES,
    MSG_CONFIRM,
    MSG_FINAL,
    MSG_HELLO,
    MSG_REPLY,
    STATUS_ACCEPT,
    STATUS_REJECT,
    HandshakeDecodeError,
    HandshakeMessageError,
    HandshakeValidationError,
    decode_confirm,
    decode_final,
    decode_hello,
    decode_reply,
    encode_confirm,
    encode_final,
    encode_hello,
    encode_reply,
)
from securesync.infrastructure.networking.replay_protection import UnsupportedVersionError
from securesync.infrastructure.networking.x25519_safety import (
    LOW_ORDER_POINTS,
    LowOrderPointError,
)

DECODERS = (decode_hello, decode_reply, decode_confirm, decode_final)

#: The only exceptions a decoder may raise for hostile input.
TYPED_ERRORS = (HandshakeMessageError, LowOrderPointError, UnsupportedVersionError)

device_ids = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs", "Cc"),
        blacklist_characters="\x00",
    ),
    min_size=1,
    max_size=16,
).filter(lambda value: len(value.encode("utf-8")) <= MAX_DEVICE_ID_BYTES)

ports = st.integers(min_value=1, max_value=65535)
#: A degenerate point is a *rejection* case, covered by TestNoCrash; a
#: round-trip test needs a key the decoder will accept.
keys = st.binary(min_size=32, max_size=32).filter(lambda value: value not in LOW_ORDER_POINTS)
nonces = st.binary(min_size=32, max_size=32)
signatures = st.binary(min_size=64, max_size=64)
macs = st.binary(min_size=32, max_size=32)


class TestNoCrash:
    @given(payload=st.binary(max_size=256))
    @settings(max_examples=150, deadline=None)
    def test_decoders_only_raise_typed_errors(self, payload: bytes) -> None:
        for decode in DECODERS:
            try:
                decode(payload)
            except TYPED_ERRORS:
                continue

    @given(payload=st.binary(min_size=2, max_size=8))
    @settings(max_examples=100, deadline=None)
    def test_a_wrong_version_is_always_rejected(self, payload: bytes) -> None:
        if payload[0] == HANDSHAKE_VERSION:
            return
        for decode in DECODERS:
            with pytest.raises(UnsupportedVersionError):
                decode(payload)

    @given(payload=st.binary(max_size=64))
    @settings(max_examples=50, deadline=None)
    def test_decoding_is_deterministic(self, payload: bytes) -> None:
        # Same bytes, same outcome: no hidden state between calls.
        for decode in DECODERS:
            first = _outcome(decode, payload)
            second = _outcome(decode, payload)
            assert first == second


class TestNoUnboundedAllocation:
    def test_an_oversized_declared_id_is_rejected_before_it_is_read(self) -> None:
        # 0xFFFF is a legal u16 but not a legal device id length. The check has
        # to happen before the body is touched, so a 2-byte length cannot make
        # the receiver wait for 64 KiB that will never arrive.
        header = bytes([HANDSHAKE_VERSION, MSG_HELLO]) + b"\x00" * 64 + struct.pack(">H", 0xFFFF)
        with pytest.raises(HandshakeValidationError):
            decode_hello(header)

    @given(
        declared=st.integers(min_value=0, max_value=0xFFFF).filter(
            lambda value: not 1 <= value <= MAX_DEVICE_ID_BYTES
        )
    )
    @settings(max_examples=100, deadline=None)
    def test_every_out_of_range_id_length_is_a_validation_error(self, declared: int) -> None:
        header = bytes([HANDSHAKE_VERSION, MSG_HELLO]) + b"\x00" * 64 + struct.pack(">H", declared)
        with pytest.raises(HandshakeValidationError):
            decode_hello(header)

    def test_a_declared_length_beyond_the_buffer_is_a_decode_error(self) -> None:
        # The length is in range, but the bytes are not there.
        header = (
            bytes([HANDSHAKE_VERSION, MSG_HELLO])
            + b"\x00" * 64
            + struct.pack(">H", MAX_DEVICE_ID_BYTES)
        )
        with pytest.raises(HandshakeDecodeError):
            decode_hello(header)


class TestRoundTrip:
    @given(
        e_i=keys,
        n_i=nonces,
        device_id=device_ids,
        identity_public_key=keys,
        transfer_port=ports,
        manifest_port=ports,
    )
    @settings(max_examples=50, deadline=None)
    def test_hello_round_trips(
        self,
        e_i: bytes,
        n_i: bytes,
        device_id: str,
        identity_public_key: bytes,
        transfer_port: int,
        manifest_port: int,
    ) -> None:
        encoded = encode_hello(
            e_i=e_i,
            n_i=n_i,
            device_id=device_id,
            identity_public_key=identity_public_key,
            transfer_port=transfer_port,
            manifest_port=manifest_port,
        )
        decoded = decode_hello(encoded)
        assert decoded.e_i == e_i
        assert decoded.n_i == n_i
        assert decoded.device_id == device_id
        assert decoded.identity_public_key == identity_public_key
        assert decoded.transfer_port == transfer_port
        assert decoded.manifest_port == manifest_port
        assert decoded.version == HANDSHAKE_VERSION
        assert (
            encode_hello(
                e_i=decoded.e_i,
                n_i=decoded.n_i,
                device_id=decoded.device_id,
                identity_public_key=decoded.identity_public_key,
                transfer_port=decoded.transfer_port,
                manifest_port=decoded.manifest_port,
            )
            == encoded
        )

    @given(
        e_r=keys,
        n_r=nonces,
        device_id=device_ids,
        identity_public_key=keys,
        transfer_port=ports,
        manifest_port=ports,
        sig_r=signatures,
        mac_r=macs,
    )
    @settings(max_examples=50, deadline=None)
    def test_reply_round_trips(
        self,
        e_r: bytes,
        n_r: bytes,
        device_id: str,
        identity_public_key: bytes,
        transfer_port: int,
        manifest_port: int,
        sig_r: bytes,
        mac_r: bytes,
    ) -> None:
        encoded = encode_reply(
            e_r=e_r,
            n_r=n_r,
            device_id=device_id,
            identity_public_key=identity_public_key,
            transfer_port=transfer_port,
            manifest_port=manifest_port,
            sig_r=sig_r,
            mac_r=mac_r,
        )
        decoded = decode_reply(encoded)
        assert decoded.device_id == device_id
        assert decoded.sig_r == sig_r
        assert decoded.mac_r == mac_r
        assert decoded.body == encoded[: len(encoded) - 96]

    @given(sig_i=signatures, mac_i=macs)
    @settings(max_examples=50, deadline=None)
    def test_confirm_round_trips(self, sig_i: bytes, mac_i: bytes) -> None:
        encoded = encode_confirm(sig_i=sig_i, mac_i=mac_i)
        decoded = decode_confirm(encoded)
        assert decoded.sig_i == sig_i
        assert decoded.mac_i == mac_i
        assert encode_confirm(sig_i=decoded.sig_i, mac_i=decoded.mac_i) == encoded

    @given(mac_f=macs, status=st.sampled_from([STATUS_ACCEPT, STATUS_REJECT]))
    @settings(max_examples=50, deadline=None)
    def test_final_round_trips(self, mac_f: bytes, status: int) -> None:
        encoded = encode_final(status=status, mac_f=mac_f)
        decoded = decode_final(encoded)
        assert decoded.status == status
        assert decoded.mac_f == mac_f


class TestStrictness:
    @given(
        e_i=keys,
        n_i=nonces,
        device_id=device_ids,
        identity_public_key=keys,
        transfer_port=ports,
        manifest_port=ports,
        extra=st.binary(min_size=1, max_size=8),
    )
    @settings(max_examples=50, deadline=None)
    def test_trailing_bytes_are_always_rejected(
        self,
        e_i: bytes,
        n_i: bytes,
        device_id: str,
        identity_public_key: bytes,
        transfer_port: int,
        manifest_port: int,
        extra: bytes,
    ) -> None:
        encoded = encode_hello(
            e_i=e_i,
            n_i=n_i,
            device_id=device_id,
            identity_public_key=identity_public_key,
            transfer_port=transfer_port,
            manifest_port=manifest_port,
        )
        with pytest.raises(HandshakeDecodeError):
            decode_hello(encoded + extra)

    @given(
        e_i=keys,
        n_i=nonces,
        device_id=device_ids,
        identity_public_key=keys,
        transfer_port=ports,
        manifest_port=ports,
        msg_type=st.sampled_from([MSG_REPLY, MSG_CONFIRM, MSG_FINAL]),
    )
    @settings(max_examples=50, deadline=None)
    def test_a_wrong_msg_type_is_rejected(
        self,
        e_i: bytes,
        n_i: bytes,
        device_id: str,
        identity_public_key: bytes,
        transfer_port: int,
        manifest_port: int,
        msg_type: int,
    ) -> None:
        encoded = bytearray(
            encode_hello(
                e_i=e_i,
                n_i=n_i,
                device_id=device_id,
                identity_public_key=identity_public_key,
                transfer_port=transfer_port,
                manifest_port=manifest_port,
            )
        )
        encoded[1] = msg_type
        with pytest.raises(HandshakeDecodeError):
            decode_hello(bytes(encoded))


class TestEncoderValidation:
    @given(device_id=st.builds(lambda prefix: "a" + prefix + "", st.text(max_size=8)))
    @settings(max_examples=50, deadline=None)
    def test_a_control_character_in_a_device_id_is_rejected(self, device_id: str) -> None:
        with pytest.raises(HandshakeValidationError):
            encode_hello(
                e_i=b"\x01" * 32,
                n_i=b"\x02" * 32,
                device_id=device_id,
                identity_public_key=b"\x03" * 32,
                transfer_port=5000,
                manifest_port=5001,
            )

    @given(device_id=st.text(min_size=65, max_size=200))
    @settings(max_examples=50, deadline=None)
    def test_an_oversized_device_id_is_rejected(self, device_id: str) -> None:
        with pytest.raises(HandshakeValidationError):
            encode_hello(
                e_i=b"\x01" * 32,
                n_i=b"\x02" * 32,
                device_id=device_id,
                identity_public_key=b"\x03" * 32,
                transfer_port=5000,
                manifest_port=5001,
            )

    @given(port=st.integers().filter(lambda value: not 1 <= value <= 65535))
    @settings(max_examples=50, deadline=None)
    def test_an_out_of_range_port_is_rejected(self, port: int) -> None:
        with pytest.raises(HandshakeValidationError):
            encode_hello(
                e_i=b"\x01" * 32,
                n_i=b"\x02" * 32,
                device_id="device-alpha",
                identity_public_key=b"\x03" * 32,
                transfer_port=port,
                manifest_port=5001,
            )

    @given(status=st.integers().filter(lambda value: value not in (0x00, 0x01)))
    @settings(max_examples=50, deadline=None)
    def test_an_invalid_status_is_rejected(self, status: int) -> None:
        with pytest.raises(HandshakeValidationError):
            encode_final(status=status, mac_f=b"\x00" * 32)


def _outcome(decode: Callable[[bytes], object], payload: bytes) -> tuple[str, str]:
    """Return a comparable description of what a decoder did."""
    try:
        decode(payload)
    except BaseException as exc:
        return ("raised", type(exc).__name__)
    return ("returned", "")
