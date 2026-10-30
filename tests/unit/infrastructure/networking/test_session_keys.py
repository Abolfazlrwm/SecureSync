"""Unit tests for the v2 role-based HKDF key schedule."""

from __future__ import annotations

import pytest

from securesync.infrastructure.networking.replay_protection import (
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    SESSION_ID_SIZE,
)
from securesync.infrastructure.networking.session_keys import (
    KEY_SIZE,
    KeyScheduleError,
    derive_directional_keys,
    derive_master,
    derive_session_id,
    derive_session_keys,
    length_prefixed,
)

SHARED_SECRET = b"\x42" * 32
SALT = b"\x01" * 16
I_PUB = b"\xaa" * 32
R_PUB = b"\xbb" * 32


def _initiator() -> object:
    return derive_session_keys(
        shared_secret=SHARED_SECRET,
        salt=SALT,
        initiator_id="dev-a",
        responder_id="dev-b",
        initiator_ephemeral_pub=I_PUB,
        responder_ephemeral_pub=R_PUB,
        role=ROLE_INITIATOR,
    )


def _responder() -> object:
    return derive_session_keys(
        shared_secret=SHARED_SECRET,
        salt=SALT,
        initiator_id="dev-a",
        responder_id="dev-b",
        initiator_ephemeral_pub=I_PUB,
        responder_ephemeral_pub=R_PUB,
        role=ROLE_RESPONDER,
    )


class TestLengthPrefixing:
    def test_prefixes_the_length(self) -> None:
        assert length_prefixed(b"abc") == b"\x00\x03abc"

    def test_empty_value_round_trips(self) -> None:
        assert length_prefixed(b"") == b"\x00\x00"

    def test_prevents_split_collisions(self) -> None:
        assert length_prefixed(b"ab") + length_prefixed(b"cd") != (
            length_prefixed(b"abc") + length_prefixed(b"d")
        )

    def test_rejects_oversized_value(self) -> None:
        with pytest.raises(KeyScheduleError):
            length_prefixed(b"x" * 0x10000)


class TestSessionId:
    def test_is_eight_bytes(self) -> None:
        sid = derive_session_id(
            SHARED_SECRET, SALT, initiator_ephemeral_pub=I_PUB, responder_ephemeral_pub=R_PUB
        )
        assert len(sid) == SESSION_ID_SIZE

    def test_is_identical_on_both_sides(self) -> None:
        assert _initiator().session_id == _responder().session_id  # type: ignore[attr-defined]

    def test_changes_when_an_ephemeral_key_changes(self) -> None:
        first = derive_session_id(
            SHARED_SECRET, SALT, initiator_ephemeral_pub=I_PUB, responder_ephemeral_pub=R_PUB
        )
        second = derive_session_id(
            SHARED_SECRET, SALT, initiator_ephemeral_pub=b"\xcc" * 32, responder_ephemeral_pub=R_PUB
        )
        assert first != second


class TestMaster:
    def test_is_32_bytes(self) -> None:
        assert (
            len(
                derive_master(
                    SHARED_SECRET,
                    SALT,
                    initiator_ephemeral_pub=I_PUB,
                    responder_ephemeral_pub=R_PUB,
                )
            )
            == KEY_SIZE
        )

    def test_depends_on_the_salt(self) -> None:
        a = derive_master(
            SHARED_SECRET, SALT, initiator_ephemeral_pub=I_PUB, responder_ephemeral_pub=R_PUB
        )
        b = derive_master(
            SHARED_SECRET,
            b"\x02" * 16,
            initiator_ephemeral_pub=I_PUB,
            responder_ephemeral_pub=R_PUB,
        )
        assert a != b


class TestDirectionalKeys:
    def test_initiator_send_equals_responder_receive(self) -> None:
        a, b = _initiator(), _responder()
        assert a.send_key == b.receive_key  # type: ignore[attr-defined]

    def test_responder_send_equals_initiator_receive(self) -> None:
        a, b = _initiator(), _responder()
        assert b.send_key == a.receive_key  # type: ignore[attr-defined]

    def test_send_and_receive_differ_within_one_side(self) -> None:
        a = _initiator()
        assert a.send_key != a.receive_key  # type: ignore[attr-defined]

    def test_both_sides_hold_the_same_pair(self) -> None:
        a, b = _initiator(), _responder()
        assert {a.send_key, a.receive_key} == {b.send_key, b.receive_key}  # type: ignore[attr-defined]

    def test_keys_are_32_bytes(self) -> None:
        a = _initiator()
        assert len(a.send_key) == KEY_SIZE  # type: ignore[attr-defined]
        assert len(a.receive_key) == KEY_SIZE  # type: ignore[attr-defined]

    def test_different_id_split_derives_different_keys(self) -> None:
        master = derive_master(
            SHARED_SECRET, SALT, initiator_ephemeral_pub=I_PUB, responder_ephemeral_pub=R_PUB
        )
        sid = derive_session_id(
            SHARED_SECRET, SALT, initiator_ephemeral_pub=I_PUB, responder_ephemeral_pub=R_PUB
        )
        ab_cd = derive_directional_keys(
            master,
            initiator_id="ab",
            responder_id="cd",
            session_id=sid,
            initiator_ephemeral_pub=I_PUB,
            responder_ephemeral_pub=R_PUB,
        )
        abc_d = derive_directional_keys(
            master,
            initiator_id="abc",
            responder_id="d",
            session_id=sid,
            initiator_ephemeral_pub=I_PUB,
            responder_ephemeral_pub=R_PUB,
        )
        assert ab_cd != abc_d

    def test_different_peers_derive_different_keys(self) -> None:
        master = derive_master(
            SHARED_SECRET, SALT, initiator_ephemeral_pub=I_PUB, responder_ephemeral_pub=R_PUB
        )
        sid = derive_session_id(
            SHARED_SECRET, SALT, initiator_ephemeral_pub=I_PUB, responder_ephemeral_pub=R_PUB
        )
        one = derive_directional_keys(
            master,
            initiator_id="dev-a",
            responder_id="dev-b",
            session_id=sid,
            initiator_ephemeral_pub=I_PUB,
            responder_ephemeral_pub=R_PUB,
        )
        two = derive_directional_keys(
            master,
            initiator_id="dev-a",
            responder_id="dev-c",
            session_id=sid,
            initiator_ephemeral_pub=I_PUB,
            responder_ephemeral_pub=R_PUB,
        )
        assert one != two

    def test_rejects_wrong_session_id_length(self) -> None:
        master = derive_master(
            SHARED_SECRET, SALT, initiator_ephemeral_pub=I_PUB, responder_ephemeral_pub=R_PUB
        )
        with pytest.raises(KeyScheduleError):
            derive_directional_keys(
                master,
                initiator_id="a",
                responder_id="b",
                session_id=b"short",
                initiator_ephemeral_pub=I_PUB,
                responder_ephemeral_pub=R_PUB,
            )


class TestRoleMapping:
    def test_invalid_role_rejected(self) -> None:
        with pytest.raises(KeyScheduleError):
            derive_session_keys(
                shared_secret=SHARED_SECRET,
                salt=SALT,
                initiator_id="dev-a",
                responder_id="dev-b",
                initiator_ephemeral_pub=I_PUB,
                responder_ephemeral_pub=R_PUB,
                role=0x77,
            )

    def test_role_is_recorded(self) -> None:
        assert _initiator().role == ROLE_INITIATOR  # type: ignore[attr-defined]
        assert _responder().role == ROLE_RESPONDER  # type: ignore[attr-defined]
