"""Tests for the X25519 low-order / all-zero rejection helpers.

The authoritative defence against contributory-behaviour attacks is the
all-zero shared-secret rejection mandated by RFC 7748 §6.1.  The
seven-point blacklist is defence-in-depth: it rejects known low-order
inputs *before* ECDH so the error is typed and early.  These tests
verify both layers, including the non-canonical encodings that an
attacker might send to bypass a naive byte-comparison check.
"""

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

    def test_non_canonical_low_order_encodings_are_included(self) -> None:
        """The three non-canonical encodings of (0,0) must be rejected.

        X25519 clamps the high bit, so ``ecff...7f``, ``edff...7f`` and
        ``eeff...7f`` all represent the same low-order point.  An attacker
        might send one of these to bypass a check that only looks for the
        canonical ``0000...00`` encoding.  They are all in the blacklist.
        """
        non_canonical = {
            bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        }
        assert non_canonical.issubset(LOW_ORDER_POINTS)
        for point in non_canonical:
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
