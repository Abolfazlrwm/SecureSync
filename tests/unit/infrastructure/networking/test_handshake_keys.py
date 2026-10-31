"""Tests for the v3 key schedule and key-confirmation MACs.

The known-answer values below are the ones published in
``docs/design/1e-test-vectors.md``: fixed X25519 seeds, fixed nonces and the
frozen ``t2`` from the message-layer KAT. That way a failure here points at the
key schedule rather than at the encoder.
"""

from __future__ import annotations

import dataclasses

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from securesync.core.protocol import ProtocolError
from securesync.infrastructure.networking.handshake_keys import (
    HandshakeKeyError,
    HandshakeSecrets,
    KeyConfirmationError,
    confirmation_mac,
    derive_handshake_secrets,
    keys_for_role,
    verify_confirmation_mac,
)
from securesync.infrastructure.networking.handshake_messages import (
    HANDSHAKE_VERSION,
    HelloMessage,
    ReplyMessage,
)
from securesync.infrastructure.networking.replay_protection import (
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    SESSION_ID_SIZE,
)
from securesync.infrastructure.networking.session_keys import KEY_SIZE
from securesync.infrastructure.networking.x25519_safety import LowOrderPointError

E_I_SEED = bytes(range(0x00, 0x20))
E_R_SEED = bytes(range(0x20, 0x40))

E_I_PUB = bytes.fromhex("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f")
E_R_PUB = bytes.fromhex("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254")
ID_PUB_I = bytes.fromhex("4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4")
ID_PUB_R = bytes.fromhex("74fca2a3b389fb1a64d9bf52cc0dd4c2964f3804c0cf7c755e8513c6db8198dc")

#: Frozen ``t2`` from the message-layer known-answer test.
T2 = bytes.fromhex("4d2c7997e9a177c99ff9c35516dbcae92a0a03bdeacecea0b1092f52f0936486")

EXPECTED_MASTER = "d65e14df0d271da9bb5d7d315e5477eecffde2f10c96689a356ccab83083d7ab"
EXPECTED_K_R = "4555af6e0feb941795f8e15993036f1ad886ff56f9ab920a89c8489f2444f585"
EXPECTED_K_I = "a2f09dd855c1d25d68c46e59cecabad9ed8a3df77942eef872174e3e8c6630dd"
EXPECTED_SESSION_ID = "37575568cab8950b"
EXPECTED_I2R = "d653f50cde85223116dc0b756ac3dcf7ddcee40eccb000a98b78c4104967bc51"
EXPECTED_R2I = "daf67e5dc9dc5594f41ec1da412d293cc17830eb5d72a7b0adf51dc18f1ee5d4"


def _shared_secret() -> bytes:
    private = X25519PrivateKey.from_private_bytes(E_I_SEED)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert public == E_I_PUB
    return private.exchange(X25519PrivateKey.from_private_bytes(E_R_SEED).public_key())


SHARED_SECRET = _shared_secret()


def _hello(**overrides: object) -> HelloMessage:
    base = HelloMessage(
        version=HANDSHAKE_VERSION,
        e_i=E_I_PUB,
        n_i=b"\x11" * 32,
        device_id="device-alpha",
        identity_public_key=ID_PUB_I,
        transfer_port=5000,
        manifest_port=5001,
        raw=b"",
    )
    return dataclasses.replace(base, **overrides)  # type: ignore[arg-type]


def _reply(**overrides: object) -> ReplyMessage:
    base = ReplyMessage(
        version=HANDSHAKE_VERSION,
        e_r=E_R_PUB,
        n_r=b"\x22" * 32,
        device_id="device-beta",
        identity_public_key=ID_PUB_R,
        transfer_port=5001,
        manifest_port=5002,
        sig_r=b"\xaa" * 64,
        mac_r=b"\xcc" * 32,
        body=b"",
        raw=b"",
    )
    return dataclasses.replace(base, **overrides)  # type: ignore[arg-type]


def _derive(
    *,
    shared_secret: bytes = SHARED_SECRET,
    hello: HelloMessage | None = None,
    reply: ReplyMessage | None = None,
    transcript_t2: bytes = T2,
) -> HandshakeSecrets:
    return derive_handshake_secrets(
        shared_secret=shared_secret,
        hello=hello if hello is not None else _hello(),
        reply=reply if reply is not None else _reply(),
        transcript_t2=transcript_t2,
    )


SECRETS = _derive()


class TestKnownAnswers:
    def test_shared_secret_is_the_expected_ecdh_output(self) -> None:
        assert SHARED_SECRET.hex() == (
            "9663aa1da97e848a914a436d04163dfbb89178f107f1b5b77ed3854203382854"
        )

    def test_master_is_frozen(self) -> None:
        assert SECRETS.master.hex() == EXPECTED_MASTER

    def test_confirmation_keys_are_frozen(self) -> None:
        assert SECRETS.responder_confirmation_key.hex() == EXPECTED_K_R
        assert SECRETS.initiator_confirmation_key.hex() == EXPECTED_K_I

    def test_session_id_is_frozen(self) -> None:
        assert SECRETS.session_id.hex() == EXPECTED_SESSION_ID

    def test_directional_keys_are_frozen(self) -> None:
        assert SECRETS.initiator_to_responder_key.hex() == EXPECTED_I2R
        assert SECRETS.responder_to_initiator_key.hex() == EXPECTED_R2I

    def test_derivation_is_deterministic(self) -> None:
        assert _derive() == SECRETS


class TestDerivation:
    def test_confirmation_keys_are_distinct(self) -> None:
        # A single shared confirmation key would let mac_r be reflected as mac_i.
        assert SECRETS.responder_confirmation_key != SECRETS.initiator_confirmation_key

    def test_directional_keys_are_distinct(self) -> None:
        assert SECRETS.initiator_to_responder_key != SECRETS.responder_to_initiator_key

    def test_session_id_has_the_expected_length(self) -> None:
        assert len(SECRETS.session_id) == SESSION_ID_SIZE

    def test_all_secret_fields_have_the_expected_lengths(self) -> None:
        for value in (
            SECRETS.master,
            SECRETS.responder_confirmation_key,
            SECRETS.initiator_confirmation_key,
            SECRETS.initiator_to_responder_key,
            SECRETS.responder_to_initiator_key,
        ):
            assert len(value) == KEY_SIZE

    def test_master_depends_on_the_transcript(self) -> None:
        other = _derive(transcript_t2=b"\x99" * 32)
        assert other.master != SECRETS.master
        assert other.session_id != SECRETS.session_id
        assert other.initiator_to_responder_key != SECRETS.initiator_to_responder_key
        assert other.responder_confirmation_key != SECRETS.responder_confirmation_key
        assert other.initiator_confirmation_key != SECRETS.initiator_confirmation_key

    def test_master_depends_on_both_nonces(self) -> None:
        assert _derive(hello=_hello(n_i=b"\x33" * 32)).master != SECRETS.master
        assert _derive(reply=_reply(n_r=b"\x44" * 32)).master != SECRETS.master

    def test_session_id_depends_on_both_nonces(self) -> None:
        assert _derive(hello=_hello(n_i=b"\x33" * 32)).session_id != SECRETS.session_id
        assert _derive(reply=_reply(n_r=b"\x44" * 32)).session_id != SECRETS.session_id

    def test_directional_keys_depend_on_both_device_ids(self) -> None:
        # Swapping the IDs must not merely reorder the same bytes: lp() keeps the
        # split unambiguous, so the derived key changes.
        swapped = _derive(hello=_hello(device_id="device-beta"))
        assert swapped.initiator_to_responder_key != SECRETS.initiator_to_responder_key

    def test_directional_keys_depend_on_both_ephemerals(self) -> None:
        other_e = bytes([E_I_PUB[0] ^ 0xFF]) + E_I_PUB[1:]
        assert (
            _derive(hello=_hello(e_i=other_e)).initiator_to_responder_key
            != SECRETS.initiator_to_responder_key
        )

    def test_different_shared_secrets_give_different_masters(self) -> None:
        other = _derive(shared_secret=bytes(range(1, 33)))
        assert other.master != SECRETS.master
        assert other.session_id != SECRETS.session_id


class TestRoleSelection:
    def test_initiator_sends_with_i2r_and_receives_with_r2i(self) -> None:
        keys = keys_for_role(SECRETS, ROLE_INITIATOR)
        assert keys.send_key == SECRETS.initiator_to_responder_key
        assert keys.receive_key == SECRETS.responder_to_initiator_key
        assert keys.session_id == SECRETS.session_id
        assert keys.role == ROLE_INITIATOR

    def test_responder_sends_with_r2i_and_receives_with_i2r(self) -> None:
        keys = keys_for_role(SECRETS, ROLE_RESPONDER)
        assert keys.send_key == SECRETS.responder_to_initiator_key
        assert keys.receive_key == SECRETS.initiator_to_responder_key
        assert keys.role == ROLE_RESPONDER

    def test_the_two_roles_are_mirror_images(self) -> None:
        initiator = keys_for_role(SECRETS, ROLE_INITIATOR)
        responder = keys_for_role(SECRETS, ROLE_RESPONDER)
        assert initiator.send_key == responder.receive_key
        assert initiator.receive_key == responder.send_key
        # Reflection protection: each side's send key differs from the other's.
        assert initiator.send_key != responder.send_key

    def test_unknown_role_is_rejected(self) -> None:
        with pytest.raises(HandshakeKeyError):
            keys_for_role(SECRETS, 0x02)


class TestConfirmationMacs:
    def test_mac_has_the_expected_length(self) -> None:
        assert len(confirmation_mac(SECRETS.responder_confirmation_key, T2)) == 32

    def test_mac_is_deterministic(self) -> None:
        first = confirmation_mac(SECRETS.responder_confirmation_key, T2)
        second = confirmation_mac(SECRETS.responder_confirmation_key, T2)
        assert first == second

    def test_verify_accepts_the_matching_mac(self) -> None:
        mac = confirmation_mac(SECRETS.responder_confirmation_key, T2)
        verify_confirmation_mac(SECRETS.responder_confirmation_key, T2, mac)

    def test_verify_rejects_a_tampered_mac(self) -> None:
        mac = bytearray(confirmation_mac(SECRETS.responder_confirmation_key, T2))
        mac[0] ^= 0x01
        with pytest.raises(KeyConfirmationError):
            verify_confirmation_mac(SECRETS.responder_confirmation_key, T2, bytes(mac))

    def test_verify_rejects_the_mac_of_a_different_transcript(self) -> None:
        mac = confirmation_mac(SECRETS.responder_confirmation_key, T2)
        with pytest.raises(KeyConfirmationError):
            verify_confirmation_mac(SECRETS.responder_confirmation_key, b"\x99" * 32, mac)

    def test_a_responder_mac_cannot_be_reflected_as_an_initiator_mac(self) -> None:
        # The whole point of separate k_r / k_i: replay mac_r where mac_i belongs.
        mac_r = confirmation_mac(SECRETS.responder_confirmation_key, T2)
        with pytest.raises(KeyConfirmationError):
            verify_confirmation_mac(SECRETS.initiator_confirmation_key, T2, mac_r)

    def test_the_two_keys_produce_different_macs_for_the_same_transcript(self) -> None:
        assert confirmation_mac(SECRETS.responder_confirmation_key, T2) != confirmation_mac(
            SECRETS.initiator_confirmation_key, T2
        )

    def test_verify_rejects_a_mac_of_the_wrong_length(self) -> None:
        with pytest.raises(HandshakeKeyError):
            verify_confirmation_mac(SECRETS.responder_confirmation_key, T2, b"\x00" * 31)

    def test_computing_with_a_short_key_is_rejected(self) -> None:
        with pytest.raises(HandshakeKeyError):
            confirmation_mac(b"\x00" * 16, T2)

    def test_computing_over_a_short_transcript_is_rejected(self) -> None:
        with pytest.raises(HandshakeKeyError):
            confirmation_mac(SECRETS.responder_confirmation_key, b"\x00" * 16)


class TestValidation:
    def test_short_shared_secret_is_rejected(self) -> None:
        with pytest.raises(HandshakeKeyError):
            _derive(shared_secret=b"\x01" * 31)

    def test_long_shared_secret_is_rejected(self) -> None:
        with pytest.raises(HandshakeKeyError):
            _derive(shared_secret=b"\x01" * 33)

    def test_all_zero_shared_secret_is_rejected_as_low_order(self) -> None:
        with pytest.raises(LowOrderPointError):
            _derive(shared_secret=b"\x00" * 32)

    def test_wrong_transcript_length_is_rejected(self) -> None:
        with pytest.raises(HandshakeKeyError):
            _derive(transcript_t2=b"\x00" * 31)

    def test_wrong_nonce_lengths_are_rejected(self) -> None:
        with pytest.raises(HandshakeKeyError):
            _derive(hello=_hello(n_i=b"\x11" * 31))
        with pytest.raises(HandshakeKeyError):
            _derive(reply=_reply(n_r=b"\x22" * 33))

    def test_every_error_is_a_protocol_error(self) -> None:
        for error in (HandshakeKeyError, KeyConfirmationError):
            assert issubclass(error, ProtocolError)
