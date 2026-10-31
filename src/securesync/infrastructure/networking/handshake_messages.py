"""Wire encoding for the v3 SIGMA-style handshake messages.

Four messages, each framed by the existing 4-byte length prefix:

- ``HELLO``   (0x01, initiator -> responder, unsigned)
- ``REPLY``   (0x02, responder -> initiator, signed + ``mac_r``)
- ``CONFIRM`` (0x03, initiator -> responder, ``sig_i`` + ``mac_i``)
- ``FINAL``   (0x04, responder -> initiator, accept/reject + ``mac_f``)

The handshake ``msg_type`` namespace is separate from
:class:`~securesync.core.protocol.PacketType`; see
``docs/design/1e-handshake.md`` §4.1. The value ``0x04`` means ``FINAL`` in
a handshake message and ``REKEY`` in a 1d frame; they never share a decoder.

Decoders raise only typed errors: :class:`HandshakeDecodeError` for
truncated/trailing bytes, :class:`HandshakeValidationError` for out-of-range
fields, :class:`~securesync.infrastructure.networking.x25519_safety.LowOrderPointError`
for degenerate keys, and ``UnsupportedVersionError`` for a version mismatch.
"""

from __future__ import annotations

import hashlib
import struct
import unicodedata
from dataclasses import dataclass
from typing import Final

from securesync.core.protocol import ProtocolError
from securesync.infrastructure.networking.replay_protection import (
    UnsupportedVersionError,
)
from securesync.infrastructure.networking.session_keys import (
    KeyScheduleError,
    length_prefixed,
)
from securesync.infrastructure.networking.x25519_safety import (
    X25519_KEY_SIZE,
    check_public_key,
)

#: Wire version of the handshake. Equal to ``CURRENT_VERSION`` after 1e.
HANDSHAKE_VERSION: Final = 3

MSG_HELLO: Final = 0x01
MSG_REPLY: Final = 0x02
MSG_CONFIRM: Final = 0x03
MSG_FINAL: Final = 0x04

STATUS_ACCEPT: Final = 0x00
STATUS_REJECT: Final = 0x01

MAX_DEVICE_ID_BYTES: Final = 64
MIN_DEVICE_ID_BYTES: Final = 1
MIN_PORT: Final = 1
MAX_PORT: Final = 65535

NONCE_SIZE: Final = 32
ED25519_PUBLIC_KEY_SIZE: Final = 32
ED25519_SIGNATURE_SIZE: Final = 64
MAC_SIZE: Final = 32

#: Domain-separation prefix for the message-1/2 transcript.
T1: Final = b"securesync-1e-handshake-v1"
#: Distinct labels for the two signatures, so one can never be replayed as
#: the other even if the transcript bytes were identical.
RESPONDER_SIG_LABEL: Final = b"securesync-1e-responder-sig"
INITIATOR_SIG_LABEL: Final = b"securesync-1e-initiator-sig"
M4_ACCEPT_LABEL: Final = b"securesync-1e-m4-accept"
M4_REJECT_LABEL: Final = b"securesync-1e-m4-reject"

_U16 = struct.Struct(">H")


class HandshakeMessageError(ProtocolError):
    """Base class for malformed or invalid handshake messages."""


class HandshakeDecodeError(HandshakeMessageError):
    """Raised when a handshake message cannot be decoded."""


class HandshakeValidationError(HandshakeMessageError):
    """Raised when a decoded or to-be-encoded field is invalid."""


@dataclass(frozen=True, slots=True)
class HelloMessage:
    """A decoded ``HELLO`` (message 1, unsigned)."""

    version: int
    e_i: bytes
    n_i: bytes
    device_id: str
    identity_public_key: bytes
    transfer_port: int
    manifest_port: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class ReplyMessage:
    """A decoded ``REPLY`` (message 2).

    ``body`` is the part covered by ``t2`` (everything up to and including
    ``manifest_port_r``); ``raw`` is the full message, including ``sig_r``
    and ``mac_r``.
    """

    version: int
    e_r: bytes
    n_r: bytes
    device_id: str
    identity_public_key: bytes
    transfer_port: int
    manifest_port: int
    sig_r: bytes
    mac_r: bytes
    body: bytes
    raw: bytes


@dataclass(frozen=True, slots=True)
class ConfirmMessage:
    """A decoded ``CONFIRM`` (message 3)."""

    version: int
    sig_i: bytes
    mac_i: bytes
    raw: bytes


@dataclass(frozen=True, slots=True)
class FinalMessage:
    """A decoded ``FINAL`` (message 4)."""

    version: int
    status: int
    mac_f: bytes
    raw: bytes


# --- validation -------------------------------------------------------------


def _validate_version(version: int) -> None:
    if version != HANDSHAKE_VERSION:
        raise UnsupportedVersionError(
            f"handshake version {version} is not supported (expected {HANDSHAKE_VERSION})"
        )


def _validate_msg_type(data: bytes, expected: int) -> None:
    if len(data) < 2:
        raise HandshakeDecodeError("message is shorter than its 2-byte header")
    _validate_version(data[0])
    if data[1] != expected:
        raise HandshakeDecodeError(f"expected msg_type 0x{expected:02x}, got 0x{data[1]:02x}")


def _validate_device_id(device_id: str) -> bytes:
    try:
        encoded = device_id.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:  # pragma: no cover - str.encode rarely fails
        raise HandshakeValidationError("device_id is not valid UTF-8") from exc
    if not encoded:
        raise HandshakeValidationError("device_id must not be empty")
    if len(encoded) > MAX_DEVICE_ID_BYTES:
        raise HandshakeValidationError(
            f"device_id is {len(encoded)} bytes, max {MAX_DEVICE_ID_BYTES}"
        )
    if any(unicodedata.category(ch) == "Cc" for ch in device_id):
        raise HandshakeValidationError("device_id contains control characters")
    return encoded


def _decode_device_id(raw: bytes) -> str:
    try:
        device_id = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HandshakeValidationError("device_id is not valid UTF-8") from exc
    if not device_id:
        raise HandshakeValidationError("device_id must not be empty")
    if len(raw) > MAX_DEVICE_ID_BYTES:
        raise HandshakeValidationError(f"device_id is {len(raw)} bytes, max {MAX_DEVICE_ID_BYTES}")
    if any(unicodedata.category(ch) == "Cc" for ch in device_id):
        raise HandshakeValidationError("device_id contains control characters")
    return device_id


def _validate_port(port: int, name: str) -> None:
    if not isinstance(port, int) or isinstance(port, bool):
        raise HandshakeValidationError(f"{name} must be an integer")
    if not MIN_PORT <= port <= MAX_PORT:
        raise HandshakeValidationError(f"{name} must be in 1..65535, got {port}")


def _validate_bytes(value: bytes, name: str, size: int) -> None:
    if len(value) != size:
        raise HandshakeValidationError(f"{name} must be {size} bytes, got {len(value)}")


def _lp(value: bytes) -> bytes:
    try:
        return length_prefixed(value)
    except KeyScheduleError as exc:
        raise HandshakeValidationError(str(exc)) from exc


def _take(data: bytes, offset: int, size: int, field: str) -> bytes:
    end = offset + size
    if end > len(data):
        raise HandshakeDecodeError(f"truncated {field}")
    return data[offset:end]


def _u16(data: bytes, offset: int, field: str) -> int:
    if offset + _U16.size > len(data):
        raise HandshakeDecodeError(f"truncated {field}")
    return int(_U16.unpack_from(data, offset)[0])


def check_not_self(
    peer_device_id: str,
    peer_identity_public_key: bytes,
    own_device_id: str,
    own_identity_public_key: bytes,
) -> None:
    """Reject a peer that claims our own device ID or identity key.

    Args:
        peer_device_id: The peer's claimed device ID.
        peer_identity_public_key: The peer's Ed25519 public key.
        own_device_id: This device's ID.
        own_identity_public_key: This device's Ed25519 public key.

    Raises:
        HandshakeValidationError: If either value equals our own.
    """
    if peer_device_id == own_device_id:
        raise HandshakeValidationError("peer device_id matches our own")
    if peer_identity_public_key == own_identity_public_key:
        raise HandshakeValidationError("peer identity key matches our own")


# --- encoders ---------------------------------------------------------------


def encode_hello(
    *,
    e_i: bytes,
    n_i: bytes,
    device_id: str,
    identity_public_key: bytes,
    transfer_port: int,
    manifest_port: int,
    version: int = HANDSHAKE_VERSION,
) -> bytes:
    """Encode a ``HELLO`` (message 1, unsigned)."""
    _validate_version(version)
    _validate_bytes(e_i, "e_i", X25519_KEY_SIZE)
    _validate_bytes(n_i, "n_i", NONCE_SIZE)
    _validate_bytes(identity_public_key, "identity_public_key", ED25519_PUBLIC_KEY_SIZE)
    _validate_port(transfer_port, "transfer_port")
    _validate_port(manifest_port, "manifest_port")
    device_id_bytes = _validate_device_id(device_id)
    return b"".join(
        (
            struct.pack(">BB", version, MSG_HELLO),
            e_i,
            n_i,
            struct.pack(">H", len(device_id_bytes)),
            device_id_bytes,
            identity_public_key,
            struct.pack(">HH", transfer_port, manifest_port),
        )
    )


def encode_reply_body(
    *,
    e_r: bytes,
    n_r: bytes,
    device_id: str,
    identity_public_key: bytes,
    transfer_port: int,
    manifest_port: int,
    version: int = HANDSHAKE_VERSION,
) -> bytes:
    """Encode the ``REPLY`` body (everything covered by ``t2``)."""
    _validate_version(version)
    _validate_bytes(e_r, "e_r", X25519_KEY_SIZE)
    _validate_bytes(n_r, "n_r", NONCE_SIZE)
    _validate_bytes(identity_public_key, "identity_public_key", ED25519_PUBLIC_KEY_SIZE)
    _validate_port(transfer_port, "transfer_port")
    _validate_port(manifest_port, "manifest_port")
    device_id_bytes = _validate_device_id(device_id)
    return b"".join(
        (
            struct.pack(">BB", version, MSG_REPLY),
            e_r,
            n_r,
            struct.pack(">H", len(device_id_bytes)),
            device_id_bytes,
            identity_public_key,
            struct.pack(">HH", transfer_port, manifest_port),
        )
    )


def encode_reply(
    *,
    e_r: bytes,
    n_r: bytes,
    device_id: str,
    identity_public_key: bytes,
    transfer_port: int,
    manifest_port: int,
    sig_r: bytes,
    mac_r: bytes,
    version: int = HANDSHAKE_VERSION,
) -> bytes:
    """Encode a full ``REPLY`` (message 2)."""
    _validate_bytes(sig_r, "sig_r", ED25519_SIGNATURE_SIZE)
    _validate_bytes(mac_r, "mac_r", MAC_SIZE)
    body = encode_reply_body(
        e_r=e_r,
        n_r=n_r,
        device_id=device_id,
        identity_public_key=identity_public_key,
        transfer_port=transfer_port,
        manifest_port=manifest_port,
        version=version,
    )
    return body + sig_r + mac_r


def encode_confirm(
    *,
    sig_i: bytes,
    mac_i: bytes,
    version: int = HANDSHAKE_VERSION,
) -> bytes:
    """Encode a ``CONFIRM`` (message 3)."""
    _validate_version(version)
    _validate_bytes(sig_i, "sig_i", ED25519_SIGNATURE_SIZE)
    _validate_bytes(mac_i, "mac_i", MAC_SIZE)
    return struct.pack(">BB", version, MSG_CONFIRM) + sig_i + mac_i


def encode_final(
    *,
    status: int,
    mac_f: bytes,
    version: int = HANDSHAKE_VERSION,
) -> bytes:
    """Encode a ``FINAL`` (message 4)."""
    _validate_version(version)
    if status not in (STATUS_ACCEPT, STATUS_REJECT):
        raise HandshakeValidationError(f"status must be 0x00 or 0x01, got {status!r}")
    _validate_bytes(mac_f, "mac_f", MAC_SIZE)
    return struct.pack(">BBB", version, MSG_FINAL, status) + mac_f


# --- decoders ---------------------------------------------------------------


def decode_hello(data: bytes) -> HelloMessage:
    """Decode a ``HELLO`` (message 1)."""
    _validate_msg_type(data, MSG_HELLO)
    offset = 2
    e_i = _take(data, offset, X25519_KEY_SIZE, "e_i")
    offset += X25519_KEY_SIZE
    n_i = _take(data, offset, NONCE_SIZE, "n_i")
    offset += NONCE_SIZE
    id_len = _u16(data, offset, "id_i_len")
    offset += _U16.size
    if not MIN_DEVICE_ID_BYTES <= id_len <= MAX_DEVICE_ID_BYTES:
        raise HandshakeValidationError(f"id_i_len must be 1..{MAX_DEVICE_ID_BYTES}, got {id_len}")
    device_id = _decode_device_id(_take(data, offset, id_len, "id_i"))
    offset += id_len
    identity_public_key = _take(data, offset, ED25519_PUBLIC_KEY_SIZE, "id_pub_i")
    offset += ED25519_PUBLIC_KEY_SIZE
    transfer_port = _u16(data, offset, "transfer_port_i")
    offset += _U16.size
    manifest_port = _u16(data, offset, "manifest_port_i")
    offset += _U16.size
    if offset != len(data):
        raise HandshakeDecodeError(f"trailing bytes after HELLO: {len(data) - offset}")
    _validate_port(transfer_port, "transfer_port_i")
    _validate_port(manifest_port, "manifest_port_i")
    check_public_key(e_i)
    return HelloMessage(
        version=data[0],
        e_i=e_i,
        n_i=n_i,
        device_id=device_id,
        identity_public_key=identity_public_key,
        transfer_port=transfer_port,
        manifest_port=manifest_port,
        raw=data,
    )


def decode_reply(data: bytes) -> ReplyMessage:
    """Decode a ``REPLY`` (message 2)."""
    _validate_msg_type(data, MSG_REPLY)
    offset = 2
    e_r = _take(data, offset, X25519_KEY_SIZE, "e_r")
    offset += X25519_KEY_SIZE
    n_r = _take(data, offset, NONCE_SIZE, "n_r")
    offset += NONCE_SIZE
    id_len = _u16(data, offset, "id_r_len")
    offset += _U16.size
    if not MIN_DEVICE_ID_BYTES <= id_len <= MAX_DEVICE_ID_BYTES:
        raise HandshakeValidationError(f"id_r_len must be 1..{MAX_DEVICE_ID_BYTES}, got {id_len}")
    device_id = _decode_device_id(_take(data, offset, id_len, "id_r"))
    offset += id_len
    identity_public_key = _take(data, offset, ED25519_PUBLIC_KEY_SIZE, "id_pub_r")
    offset += ED25519_PUBLIC_KEY_SIZE
    transfer_port = _u16(data, offset, "transfer_port_r")
    offset += _U16.size
    manifest_port = _u16(data, offset, "manifest_port_r")
    offset += _U16.size
    body_end = offset
    sig_r = _take(data, offset, ED25519_SIGNATURE_SIZE, "sig_r")
    offset += ED25519_SIGNATURE_SIZE
    mac_r = _take(data, offset, MAC_SIZE, "mac_r")
    offset += MAC_SIZE
    if offset != len(data):
        raise HandshakeDecodeError(f"trailing bytes after REPLY: {len(data) - offset}")
    _validate_port(transfer_port, "transfer_port_r")
    _validate_port(manifest_port, "manifest_port_r")
    check_public_key(e_r)
    return ReplyMessage(
        version=data[0],
        e_r=e_r,
        n_r=n_r,
        device_id=device_id,
        identity_public_key=identity_public_key,
        transfer_port=transfer_port,
        manifest_port=manifest_port,
        sig_r=sig_r,
        mac_r=mac_r,
        body=data[:body_end],
        raw=data,
    )


def decode_confirm(data: bytes) -> ConfirmMessage:
    """Decode a ``CONFIRM`` (message 3)."""
    _validate_msg_type(data, MSG_CONFIRM)
    offset = 2
    sig_i = _take(data, offset, ED25519_SIGNATURE_SIZE, "sig_i")
    offset += ED25519_SIGNATURE_SIZE
    mac_i = _take(data, offset, MAC_SIZE, "mac_i")
    offset += MAC_SIZE
    if offset != len(data):
        raise HandshakeDecodeError(f"trailing bytes after CONFIRM: {len(data) - offset}")
    return ConfirmMessage(version=data[0], sig_i=sig_i, mac_i=mac_i, raw=data)


def decode_final(data: bytes) -> FinalMessage:
    """Decode a ``FINAL`` (message 4)."""
    _validate_msg_type(data, MSG_FINAL)
    offset = 2
    status = _take(data, offset, 1, "status")[0]
    offset += 1
    if status not in (STATUS_ACCEPT, STATUS_REJECT):
        raise HandshakeValidationError(f"status must be 0x00 or 0x01, got {status}")
    mac_f = _take(data, offset, MAC_SIZE, "mac_f")
    offset += MAC_SIZE
    if offset != len(data):
        raise HandshakeDecodeError(f"trailing bytes after FINAL: {len(data) - offset}")
    return FinalMessage(version=data[0], status=status, mac_f=mac_f, raw=data)


# --- transcripts ------------------------------------------------------------


def _hash(prefix: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(prefix)
    for part in parts:
        digest.update(_lp(part))
    return digest.digest()


def transcript_t2(m1: bytes, m2body: bytes) -> bytes:
    """``H(T1 ‖ lp(m1) ‖ lp(m2body))``."""
    return _hash(T1, m1, m2body)


def transcript_t2s(t2: bytes, sig_r: bytes) -> bytes:
    """``H(t2 ‖ lp(sig_r))``."""
    return _hash(t2, sig_r)


def transcript_t3(t2s: bytes, mac_r: bytes) -> bytes:
    """``H(t2s ‖ lp(mac_r))``."""
    return _hash(t2s, mac_r)


def transcript_t3s(t3: bytes, sig_i: bytes) -> bytes:
    """``H(t3 ‖ lp(sig_i))``."""
    return _hash(t3, sig_i)


def transcript_final(t3s: bytes, mac_i: bytes) -> bytes:
    """``H(t3s ‖ lp(mac_i))``."""
    return _hash(t3s, mac_i)


def transcript_m4_accept(t_final: bytes) -> bytes:
    """``H(t_final ‖ lp("securesync-1e-m4-accept"))``."""
    return _hash(t_final, M4_ACCEPT_LABEL)


def transcript_m4_reject(t2s: bytes, m3_raw: bytes) -> bytes:
    """``H(t2s ‖ lp(m3_raw) ‖ lp("securesync-1e-m4-reject"))``."""
    return _hash(t2s, m3_raw, M4_REJECT_LABEL)


def signed_responder(t2: bytes) -> bytes:
    """The bytes ``sig_r`` signs: ``lp(responder-label) ‖ t2``."""
    return _lp(RESPONDER_SIG_LABEL) + t2


def signed_initiator(t2s: bytes) -> bytes:
    """The bytes ``sig_i`` signs: ``lp(initiator-label) ‖ t2s``."""
    return _lp(INITIATOR_SIG_LABEL) + t2s
