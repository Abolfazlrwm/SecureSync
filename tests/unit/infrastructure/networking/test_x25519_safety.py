"""Tests for the X25519 low-order / all-zero rejection helpers."""

from __future__ import annotations

import pytest

from securesync.infrastructure.networking.x25519_safety import (
    LOW_ORDER_POINTS,
    LowOrderPointError,
    check_public_key,
    check_shared_secret,
)


class TestLowOrderPoints:
    def test_the_seven_known_points_are_rejected(self) -> None:
        assert len(LOW_ORDER_POINTS) == 7
        for point in LOW_ORDER_POINTS:
            with pytest.raises(LowOrderPointError):
                check_public_key(point)

    def test_a_valid_point_is_accepted(self) -> None:
        check_public_key(
            bytes.fromhex("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f")
        )

    def test_wrong_length_is_rejected(self) -> None:
        with pytest.raises(LowOrderPointError):
            check_public_key(b"\x01" * 31)
        with pytest.raises(LowOrderPointError):
            check_public_key(b"\x01" * 33)

    def test_all_zero_shared_secret_is_rejected(self) -> None:
        with pytest.raises(LowOrderPointError):
            check_shared_secret(bytes(32))

    def test_non_zero_shared_secret_is_accepted(self) -> None:
        check_shared_secret(b"\x01" * 32)

    def test_shared_secret_wrong_length_is_rejected(self) -> None:
        with pytest.raises(LowOrderPointError):
            check_shared_secret(b"\x01" * 16)
