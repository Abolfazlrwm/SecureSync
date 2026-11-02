"""Tests for the v3 handshake message encoding, validation and transcripts.

The known-answer vectors below are frozen in
``docs/design/1e-test-vectors.md``. They are deterministic: the ephemeral
and identity keys come from fixed seeds and every nonce is fixed.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from securesync.core.protocol import ProtocolError
from securesync.infrastructure.networking import handshake_messages as hm
from securesync.infrastructure.networking.replay_protection import (
    UnsupportedVersionError,
)
from securesync.infrastructure.networking.x25519_safety import LowOrderPointError

E_I_SEED = bytes(range(32))
E_R_SEED = bytes(range(32, 64))
ID_SEED_I = bytes(0xA0 + i for i in range(32))
ID_SEED_R = bytes(0xB0 + i for i in range(32))

E_I_PUB = x25519.X25519PrivateKey.from_private_bytes(E_I_SEED).public_key().public_bytes_raw()
E_R_PUB = x25519.X25519PrivateKey.from_private_bytes(E_R_SEED).public_key().public_bytes_raw()
ID_PUB_I = ed25519.Ed25519PrivateKey.from_private_bytes(ID_SEED_I).public_key().public_bytes_raw()
ID_PUB_R = ed25519.Ed25519PrivateKey.from_private_bytes(ID_SEED_R).public_key().public_bytes_raw()

N_I = b"\x11" * 32
N_R = b"\x22" * 32
SIG_R = b"\xaa" * 64
SIG_I = b"\xbb" * 64
MAC_R = b"\xcc" * 32
MAC_I = b"\xdd" * 32
MAC_F = b"\xee" * 32
ID_I = "device-alpha"
ID_R = "device-beta"
PORT_I = 5000
PORT_R = 5001

M1_HEX = (
    "03018f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
    "1111111111111111111111111111111111111111111111111111111111111111"
    "000c6465766963652d616c706861"
    "4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4"
    "13881389"
)
M2_HEX = (
    "0302358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd16"
    "6254222222222222222222222222222222222222222222222222222222222222"
    "2222000b6465766963652d6265746174fca2a3b389fb1a64d9bf52cc0dd4c296"
    "4f3804c0cf7c755e8513c6db8198dc1389138aaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaacccccccccccccccccccccccccc"
    "cccccccccccccccccccccccccccccccccccccc"
)
M3_HEX = (
    "0303"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)
M4_HEX = "030400eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
T2_HEX = "4d2c7997e9a177c99ff9c35516dbcae92a0a03bdeacecea0b1092f52f0936486"
T2S_HEX = "7c2ee345f5c0589a1e1eb7762dcaa029cfc00c3ab733a72dc51a72c0e881b079"
T3_HEX = "dcf142ee4ed735e67a1b7e16f2dcf5e307727910db57b9710f6eede55f69aaa1"
T3S_HEX = "5ca3818888f39811a0ddf5fad188dbc8a564b896d92ba81a7ce44f8a3e0a1a69"
T_FINAL_HEX = "6a990fd748d5c02415175ce9623e92c7410d25630e1d0458f7f8573f56921fe3"
T4_HEX = "1879942edd44e06245163a7a27ef02a9c1c58f821c8db95aada250d46a546e15"
SIGNED_R_HEX = (
    "001b73656375726573796e632d31652d726573706f6e6465722d736967"
    "4d2c7997e9a177c99ff9c35516dbcae92a0a03bdeacecea0b1092f52f0936486"
)
SIGNED_I_HEX = (
    "001b73656375726573796e632d31652d696e69746961746f722d736967"
    "7c2ee345f5c0589a1e1eb7762dcaa029cfc00c3ab733a72dc51a72c0e881b079"
)


def _m1() -> bytes:
    return hm.encode_hello(
        e_i=E_I_PUB,
        n_i=N_I,
        device_id=ID_I,
        identity_public_key=ID_PUB_I,
        transfer_port=PORT_I,
        manifest_port=PORT_I + 1,
    )


def _m2body() -> bytes:
    return hm.encode_reply_body(
        e_r=E_R_PUB,
        n_r=N_R,
        device_id=ID_R,
        identity_public_key=ID_PUB_R,
        transfer_port=PORT_R,
        manifest_port=PORT_R + 1,
    )


def _m2() -> bytes:
    return hm.encode_reply(
        e_r=E_R_PUB,
        n_r=N_R,
        device_id=ID_R,
        identity_public_key=ID_PUB_R,
        transfer_port=PORT_R,
        manifest_port=PORT_R + 1,
        sig_r=SIG_R,
        mac_r=MAC_R,
    )


def _m3() -> bytes:
    return hm.encode_confirm(sig_i=SIG_I, mac_i=MAC_I)


def _m4() -> bytes:
    return hm.encode_final(status=hm.STATUS_ACCEPT, mac_f=MAC_F)


class TestKnownAnswers:
    def test_message_bytes_are_frozen(self) -> None:
        assert _m1().hex() == M1_HEX
        assert _m2().hex() == M2_HEX
        assert _m3().hex() == M3_HEX
        assert _m4().hex() == M4_HEX

    def test_message_lengths_match_the_spec(self) -> None:
        assert len(_m1()) == 104 + len(ID_I)
        assert len(_m2()) == 200 + len(ID_R)
        assert len(_m3()) == 98
        assert len(_m4()) == 35

    def test_transcripts_are_frozen(self) -> None:
        m1 = _m1()
        t2 = hm.transcript_t2(m1, _m2body())
        t2s = hm.transcript_t2s(t2, SIG_R)
        t3 = hm.transcript_t3(t2s, MAC_R)
        t3s = hm.transcript_t3s(t3, SIG_I)
        t_final = hm.transcript_final(t3s, MAC_I)
        t4 = hm.transcript_m4_accept(t_final)
        assert t2.hex() == T2_HEX
        assert t2s.hex() == T2S_HEX
        assert t3.hex() == T3_HEX
        assert t3s.hex() == T3S_HEX
        assert t_final.hex() == T_FINAL_HEX
        assert t4.hex() == T4_HEX

    def test_signature_payloads_are_domain_separated(self) -> None:
        m1 = _m1()
        t2 = hm.transcript_t2(m1, _m2body())
        t2s = hm.transcript_t2s(t2, SIG_R)
        assert hm.signed_responder(t2).hex() == SIGNED_R_HEX
        assert hm.signed_initiator(t2s).hex() == SIGNED_I_HEX
        assert hm.signed_responder(t2) != hm.signed_initiator(t2s)


class TestRoundTrip:
    def test_hello_round_trips(self) -> None:
        decoded = hm.decode_hello(_m1())
        assert decoded.version == hm.HANDSHAKE_VERSION
        assert decoded.e_i == E_I_PUB
        assert decoded.n_i == N_I
        assert decoded.device_id == ID_I
        assert decoded.identity_public_key == ID_PUB_I
        assert decoded.transfer_port == PORT_I
        assert decoded.manifest_port == PORT_I + 1
        assert decoded.raw == _m1()

    def test_reply_round_trips(self) -> None:
        decoded = hm.decode_reply(_m2())
        assert decoded.e_r == E_R_PUB
        assert decoded.n_r == N_R
        assert decoded.device_id == ID_R
        assert decoded.identity_public_key == ID_PUB_R
        assert decoded.transfer_port == PORT_R
        assert decoded.manifest_port == PORT_R + 1
        assert decoded.sig_r == SIG_R
        assert decoded.mac_r == MAC_R
        assert decoded.body == _m2body()
        assert decoded.raw == _m2()

    def test_confirm_round_trips(self) -> None:
        decoded = hm.decode_confirm(_m3())
        assert decoded.sig_i == SIG_I
        assert decoded.mac_i == MAC_I
        assert decoded.raw == _m3()

    def test_final_round_trips(self) -> None:
        decoded = hm.decode_final(_m4())
        assert decoded.status == hm.STATUS_ACCEPT
        assert decoded.mac_f == MAC_F
        assert decoded.raw == _m4()

    def test_reject_final_round_trips(self) -> None:
        raw = hm.encode_final(status=hm.STATUS_REJECT, mac_f=MAC_F)
        assert hm.decode_final(raw).status == hm.STATUS_REJECT


class TestValidation:
    def test_empty_device_id_is_rejected(self) -> None:
        with pytest.raises(hm.HandshakeValidationError):
            hm.encode_hello(
                e_i=E_I_PUB,
                n_i=N_I,
                device_id="",
                identity_public_key=ID_PUB_I,
                transfer_port=PORT_I,
                manifest_port=PORT_I,
            )

    def test_too_long_device_id_is_rejected(self) -> None:
        with pytest.raises(hm.HandshakeValidationError):
            hm.encode_hello(
                e_i=E_I_PUB,
                n_i=N_I,
                device_id="a" * (hm.MAX_DEVICE_ID_BYTES + 1),
                identity_public_key=ID_PUB_I,
                transfer_port=PORT_I,
                manifest_port=PORT_I,
            )

    def test_control_characters_are_rejected(self) -> None:
        for bad in ("bad\x00id", "bad\x7fid", "bad\nid"):
            with pytest.raises(hm.HandshakeValidationError):
                hm.encode_hello(
                    e_i=E_I_PUB,
                    n_i=N_I,
                    device_id=bad,
                    identity_public_key=ID_PUB_I,
                    transfer_port=PORT_I,
                    manifest_port=PORT_I,
                )

    def test_port_zero_is_rejected(self) -> None:
        with pytest.raises(hm.HandshakeValidationError):
            hm.encode_hello(
                e_i=E_I_PUB,
                n_i=N_I,
                device_id=ID_I,
                identity_public_key=ID_PUB_I,
                transfer_port=0,
                manifest_port=PORT_I,
            )

    def test_port_above_65535_is_rejected(self) -> None:
        with pytest.raises(hm.HandshakeValidationError):
            hm.encode_hello(
                e_i=E_I_PUB,
                n_i=N_I,
                device_id=ID_I,
                identity_public_key=ID_PUB_I,
                transfer_port=65536,
                manifest_port=PORT_I,
            )

    def test_unsupported_version_is_rejected(self) -> None:
        with pytest.raises(UnsupportedVersionError):
            hm.encode_hello(
                e_i=E_I_PUB,
                n_i=N_I,
                device_id=ID_I,
                identity_public_key=ID_PUB_I,
                transfer_port=PORT_I,
                manifest_port=PORT_I,
                version=2,
            )

    def test_v2_peer_is_rejected_cleanly(self) -> None:
        v2_hello = b"\x82" + b"\xa9device_id"  # msgpack fixmap first byte
        with pytest.raises(UnsupportedVersionError):
            hm.decode_hello(v2_hello)

    def test_wrong_msg_type_is_a_decode_error(self) -> None:
        with pytest.raises(hm.HandshakeDecodeError):
            hm.decode_reply(_m1())

    def test_truncated_message_is_a_decode_error(self) -> None:
        with pytest.raises(hm.HandshakeDecodeError):
            hm.decode_hello(_m1()[:-1])

    def test_trailing_bytes_are_rejected(self) -> None:
        with pytest.raises(hm.HandshakeDecodeError):
            hm.decode_hello(_m1() + b"\x00")

    def test_low_order_point_is_rejected(self) -> None:
        raw = hm.encode_hello(
            e_i=bytes(32),
            n_i=N_I,
            device_id=ID_I,
            identity_public_key=ID_PUB_I,
            transfer_port=PORT_I,
            manifest_port=PORT_I,
        )
        with pytest.raises(LowOrderPointError):
            hm.decode_hello(raw)

    def test_invalid_utf8_device_id_is_rejected(self) -> None:
        raw = (
            b"\x03\x01" + E_I_PUB + N_I + b"\x00\x02" + b"\xff\xfe" + ID_PUB_I + b"\x13\x88\x13\x89"
        )
        with pytest.raises(hm.HandshakeValidationError):
            hm.decode_hello(raw)

    def test_lp_overflow_is_rejected(self) -> None:
        with pytest.raises(hm.HandshakeValidationError):
            hm.transcript_t2(b"\x00" * 0x10000, b"")

    def test_self_connection_is_rejected(self) -> None:
        with pytest.raises(hm.HandshakeValidationError):
            hm.check_not_self("me", ID_PUB_I, "me", ID_PUB_R)
        with pytest.raises(hm.HandshakeValidationError):
            hm.check_not_self("peer", ID_PUB_I, "me", ID_PUB_I)

    def test_distinct_peer_is_accepted(self) -> None:
        hm.check_not_self("peer", ID_PUB_I, "me", ID_PUB_R)

    def test_invalid_status_is_rejected(self) -> None:
        with pytest.raises(hm.HandshakeValidationError):
            hm.encode_final(status=0x02, mac_f=MAC_F)
        raw = b"\x03\x04\x02" + MAC_F
        with pytest.raises(hm.HandshakeValidationError):
            hm.decode_final(raw)

    def test_all_errors_are_protocol_errors(self) -> None:
        # A decoder must never leak a struct/Unicode error.
        for raw in (b"", b"\x03", b"\x03\x01", b"\x03\x01" + b"\x00" * 200):
            with pytest.raises(ProtocolError):
                hm.decode_hello(raw)
