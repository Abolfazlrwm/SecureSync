"""Reject low-order X25519 public keys and all-zero shared secrets.

X25519 has no built-in contributory-behaviour check: a peer can send a
low-order point and force the shared secret into a small, predictable set
(often all zeros). ``cryptography`` raises ``ValueError`` for the seven
distinct low-order x-coordinates, but we check explicitly so the error is
typed and so the guarantee does not depend on a library detail.

The seven values below are the distinct x-coordinates of the eight points
of order dividing 8 (x and -x share an x-coordinate on a Montgomery curve).
Verified against libsodium 1.6.2 and ``cryptography`` 46.x on 2026-10-31.
"""

from __future__ import annotations

from typing import Final

from securesync.core.protocol import ProtocolError

X25519_KEY_SIZE: Final = 32

#: The seven distinct low-order x-coordinates. ``cryptography``/libsodium
#: reject all seven; the eighth algebraic point shares an x-coordinate.
LOW_ORDER_POINTS: Final[frozenset[bytes]] = frozenset(
    {
        bytes(32),
        b"\x01" + bytes(31),
        bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    }
)


class LowOrderPointError(ProtocolError):
    """Raised when an X25519 public key or shared secret is degenerate."""


def check_public_key(public_key: bytes) -> None:
    """Reject a wrong-length or low-order X25519 public key.

    Args:
        public_key: The raw 32-byte X25519 public key.

    Raises:
        LowOrderPointError: If the key is the wrong length or is one of the
            seven known low-order points.
    """
    if len(public_key) != X25519_KEY_SIZE:
        raise LowOrderPointError(
            f"X25519 public key must be {X25519_KEY_SIZE} bytes, got {len(public_key)}"
        )
    if public_key in LOW_ORDER_POINTS:
        raise LowOrderPointError("X25519 public key is a known low-order point")


def check_shared_secret(shared_secret: bytes) -> None:
    """Reject an all-zero X25519 shared secret.

    Args:
        shared_secret: The raw 32-byte ECDH output.

    Raises:
        LowOrderPointError: If the secret is the wrong length or all zeros.
    """
    if len(shared_secret) != X25519_KEY_SIZE:
        raise LowOrderPointError(
            f"X25519 shared secret must be {X25519_KEY_SIZE} bytes, got {len(shared_secret)}"
        )
    if shared_secret == bytes(X25519_KEY_SIZE):
        raise LowOrderPointError("X25519 shared secret is all zeros")
