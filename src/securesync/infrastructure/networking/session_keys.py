"""Role-based key schedule for the v2 wire protocol (HKDF).

Both peers derive the same material from the ECDH shared secret, but each ends
up with a *different* key for each direction. That is what stops a captured
frame from being reflected: the initiator's send key is not the responder's send
key, so a frame cannot be turned around and replayed back at its sender.

Every variable-length field is length-prefixed. Raw concatenation would make
``("ab", "cd")`` and ``("abc", "d")`` hash identically, so two different
``(initiator_id, responder_id)`` splits could derive the same key — there is a
test for exactly that.

```text
master     = HKDF(shared_secret, salt,
                  lp("securesync-master-v2") ‖ lp(i_pub) ‖ lp(r_pub))
session_id = first 8 bytes of HKDF(shared_secret, salt,
                  lp("securesync-session-id") ‖ lp(i_pub) ‖ lp(r_pub))
i2r_key    = HKDF(master, lp("securesync-initiator-to-responder")
                  ‖ lp(i_id) ‖ lp(r_id) ‖ session_id ‖ lp(i_pub) ‖ lp(r_pub))
r2i_key    = HKDF(master, lp("securesync-responder-to-initiator")
                  ‖ lp(i_id) ‖ lp(r_id) ‖ session_id ‖ lp(i_pub) ‖ lp(r_pub))
```
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from securesync.infrastructure.networking.replay_protection import (
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    SESSION_ID_SIZE,
)

#: Length of a derived AEAD key, in bytes (AES-256-GCM / ChaCha20-Poly1305).
KEY_SIZE: Final = 32

_MASTER_INFO: Final = b"securesync-master-v2"
_SESSION_ID_INFO: Final = b"securesync-session-id"
_I2R_INFO: Final = b"securesync-initiator-to-responder"
_R2I_INFO: Final = b"securesync-responder-to-initiator"


class KeyScheduleError(Exception):
    """Raised when the key schedule cannot derive a session's keys."""


def length_prefixed(value: bytes) -> bytes:
    """Encode ``value`` as a 2-byte big-endian length followed by the bytes.

    Args:
        value: The bytes to encode.

    Returns:
        The length-prefixed encoding.

    Raises:
        KeyScheduleError: If ``value`` is longer than 65535 bytes.
    """
    if len(value) > 0xFFFF:
        raise KeyScheduleError(f"value too long for a 2-byte length prefix: {len(value)}")
    return struct.pack(">H", len(value)) + value


def _lp_str(value: str) -> bytes:
    return length_prefixed(value.encode("utf-8"))


def _hkdf(secret: bytes, salt: bytes, info: bytes, length: int = KEY_SIZE) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(secret)


def derive_master(
    shared_secret: bytes,
    salt: bytes,
    *,
    initiator_ephemeral_pub: bytes,
    responder_ephemeral_pub: bytes,
) -> bytes:
    """Derive the per-handshake master secret.

    Args:
        shared_secret: The X25519 ECDH output.
        salt: The handshake salt.
        initiator_ephemeral_pub: The initiator's ephemeral public key.
        responder_ephemeral_pub: The responder's ephemeral public key.

    Returns:
        A 32-byte master secret.
    """
    info = (
        length_prefixed(_MASTER_INFO)
        + length_prefixed(initiator_ephemeral_pub)
        + length_prefixed(responder_ephemeral_pub)
    )
    return _hkdf(shared_secret, salt, info)


def derive_session_id(
    shared_secret: bytes,
    salt: bytes,
    *,
    initiator_ephemeral_pub: bytes,
    responder_ephemeral_pub: bytes,
) -> bytes:
    """Derive the 8-byte session identifier.

    The identifier depends only on material both peers hold, so both sides
    compute the same value without transmitting it during the handshake.

    Args:
        shared_secret: The X25519 ECDH output.
        salt: The handshake salt.
        initiator_ephemeral_pub: The initiator's ephemeral public key.
        responder_ephemeral_pub: The responder's ephemeral public key.

    Returns:
        Exactly :data:`SESSION_ID_SIZE` bytes.
    """
    info = (
        length_prefixed(_SESSION_ID_INFO)
        + length_prefixed(initiator_ephemeral_pub)
        + length_prefixed(responder_ephemeral_pub)
    )
    return _hkdf(shared_secret, salt, info, length=SESSION_ID_SIZE)


def derive_directional_keys(
    master: bytes,
    *,
    initiator_id: str,
    responder_id: str,
    session_id: bytes,
    initiator_ephemeral_pub: bytes,
    responder_ephemeral_pub: bytes,
) -> tuple[bytes, bytes]:
    """Derive the ``(initiator_to_responder, responder_to_initiator)`` keys.

    Args:
        master: The per-handshake master secret.
        initiator_id: The initiator's device ID.
        responder_id: The responder's device ID.
        session_id: The 8-byte session identifier.
        initiator_ephemeral_pub: The initiator's ephemeral public key.
        responder_ephemeral_pub: The responder's ephemeral public key.

    Returns:
        ``(i2r_key, r2i_key)``, each :data:`KEY_SIZE` bytes.

    Raises:
        KeyScheduleError: If ``session_id`` is the wrong length.
    """
    if len(session_id) != SESSION_ID_SIZE:
        raise KeyScheduleError(f"session_id must be {SESSION_ID_SIZE} bytes, got {len(session_id)}")
    common = (
        _lp_str(initiator_id)
        + _lp_str(responder_id)
        + session_id
        + length_prefixed(initiator_ephemeral_pub)
        + length_prefixed(responder_ephemeral_pub)
    )
    i2r = _hkdf(master, b"", length_prefixed(_I2R_INFO) + common)
    r2i = _hkdf(master, b"", length_prefixed(_R2I_INFO) + common)
    return i2r, r2i


@dataclass(frozen=True, slots=True)
class SessionKeys:
    """The keys one side of a handshake should use.

    Attributes:
        session_id: The 8-byte session identifier.
        send_key: Key for messages this device sends.
        receive_key: Key for messages this device receives.
        role: :data:`ROLE_INITIATOR` or :data:`ROLE_RESPONDER` for this device.
    """

    session_id: bytes
    send_key: bytes
    receive_key: bytes
    role: int


def derive_session_keys(
    *,
    shared_secret: bytes,
    salt: bytes,
    initiator_id: str,
    responder_id: str,
    initiator_ephemeral_pub: bytes,
    responder_ephemeral_pub: bytes,
    role: int,
) -> SessionKeys:
    """Derive one side's send/receive keys from the handshake material.

    Args:
        shared_secret: The X25519 ECDH output.
        salt: The handshake salt.
        initiator_id: The initiator's device ID.
        responder_id: The responder's device ID.
        initiator_ephemeral_pub: The initiator's ephemeral public key.
        responder_ephemeral_pub: The responder's ephemeral public key.
        role: This device's role, one of ``ROLE_INITIATOR`` / ``ROLE_RESPONDER``.

    Returns:
        The :class:`SessionKeys` for this device.

    Raises:
        KeyScheduleError: If ``role`` is not a known role.
    """
    master = derive_master(
        shared_secret,
        salt,
        initiator_ephemeral_pub=initiator_ephemeral_pub,
        responder_ephemeral_pub=responder_ephemeral_pub,
    )
    session_id = derive_session_id(
        shared_secret,
        salt,
        initiator_ephemeral_pub=initiator_ephemeral_pub,
        responder_ephemeral_pub=responder_ephemeral_pub,
    )
    i2r, r2i = derive_directional_keys(
        master,
        initiator_id=initiator_id,
        responder_id=responder_id,
        session_id=session_id,
        initiator_ephemeral_pub=initiator_ephemeral_pub,
        responder_ephemeral_pub=responder_ephemeral_pub,
    )
    if role == ROLE_INITIATOR:
        return SessionKeys(session_id=session_id, send_key=i2r, receive_key=r2i, role=role)
    if role == ROLE_RESPONDER:
        return SessionKeys(session_id=session_id, send_key=r2i, receive_key=i2r, role=role)
    raise KeyScheduleError(f"invalid role {role!r}")
