"""Binary wire protocol for SecureSync.

Defines the header layout, packet types, and serialization logic for
peer-to-peer communication.
"""

from __future__ import annotations

import struct
import time
import zlib
from dataclasses import dataclass, replace
from enum import IntEnum, unique
from typing import Any, Final

import msgpack  # type: ignore[import-untyped]

MAGIC: Final = 0x53594E43  # "SYNC"
HEADER_SIZE: Final = 32
CURRENT_VERSION: Final = 1


@unique
class PacketType(IntEnum):
    """Supported packet types for the wire protocol."""

    HELLO = 0x01
    KEY_EXCHANGE = 0x02
    AUTH = 0x03
    FILE_MANIFEST = 0x10
    CHUNK_REQUEST = 0x11
    CHUNK_DATA = 0x12
    HEARTBEAT = 0x20
    PEER_LIST = 0x21
    ERROR = 0xF0
    CLOSE = 0xFF


class ProtocolError(Exception):
    """Base class for all wire-protocol errors."""


class InvalidHeaderError(ProtocolError):
    """Raised when a header is the wrong size or has a bad magic number."""


class PayloadIntegrityError(ProtocolError):
    """Raised when a decoded payload's CRC32 doesn't match its header."""


@dataclass(frozen=True, slots=True)
class PacketHeader:
    """The fixed-size 32-byte binary header.

    Attributes:
        version: Protocol version.
        packet_type: The type of packet.
        flags: Bitfield for compression, encryption, etc.
        message_id: Unique ID for request/response correlation.
        payload_length: Length of the following payload.
        timestamp: Sender's Unix timestamp in ms.
        crc32: CRC32 of the payload.
    """

    version: int
    packet_type: PacketType
    flags: int
    message_id: int
    payload_length: int
    timestamp: int
    crc32: int

    def pack(self) -> bytes:
        """Serialize the header to 32 bytes."""
        return struct.pack(
            ">IBBHQIQI",
            MAGIC,
            self.version,
            self.packet_type.value,
            self.flags,
            self.message_id,
            self.payload_length,
            self.timestamp,
            self.crc32,
        )

    @classmethod
    def unpack(cls, data: bytes) -> PacketHeader:
        """Deserialize a 32-byte header.

        Raises:
            InvalidHeaderError: If ``data`` isn't 32 bytes, or its
                magic number doesn't match :data:`MAGIC`.
        """
        if len(data) != HEADER_SIZE:
            raise InvalidHeaderError(f"Invalid header size: {len(data)}")

        magic, version, p_type, flags, msg_id, p_len, ts, crc = struct.unpack(">IBBHQIQI", data)

        if magic != MAGIC:
            raise InvalidHeaderError(f"Invalid magic number: {hex(magic)}")

        return cls(
            version=version,
            packet_type=PacketType(p_type),
            flags=flags,
            message_id=msg_id,
            payload_length=p_len,
            timestamp=ts,
            crc32=crc,
        )


@dataclass(frozen=True, slots=True)
class Packet:
    """A complete SecureSync packet (header + payload)."""

    header: PacketHeader
    payload: dict[str, Any]

    def encode(self) -> bytes:
        """Encode the packet to binary.

        ``header.payload_length`` and ``header.crc32`` are recomputed
        from the actual serialized payload before encoding — a header
        built with stale or placeholder values (e.g. ``payload_length=0``)
        is corrected automatically, so callers never need to compute
        either field themselves.

        Returns:
            The encoded header (32 bytes) followed by the msgpack-encoded payload.
        """
        payload_bytes: bytes = msgpack.packb(self.payload)
        header = replace(
            self.header,
            payload_length=len(payload_bytes),
            crc32=zlib.crc32(payload_bytes),
        )
        return header.pack() + payload_bytes

    @classmethod
    def decode(cls, data: bytes) -> Packet:
        """Decode a complete packet (header + payload) from binary.

        Args:
            data: The full packet bytes, as produced by :meth:`encode`.

        Returns:
            The decoded :class:`Packet`.

        Raises:
            InvalidHeaderError: If the header is malformed.
            PayloadIntegrityError: If the payload's CRC32 doesn't
                match the header, or its length doesn't match
                ``header.payload_length``.
        """
        header = PacketHeader.unpack(data[:HEADER_SIZE])
        payload_bytes = data[HEADER_SIZE : HEADER_SIZE + header.payload_length]

        if len(payload_bytes) != header.payload_length:
            raise PayloadIntegrityError(
                f"expected {header.payload_length} payload bytes, got {len(payload_bytes)}"
            )
        if zlib.crc32(payload_bytes) != header.crc32:
            raise PayloadIntegrityError("payload CRC32 does not match header")

        payload: dict[str, Any] = msgpack.unpackb(payload_bytes, raw=False)
        return cls(header=header, payload=payload)


def make_header(packet_type: PacketType, message_id: int, *, flags: int = 0) -> PacketHeader:
    """Build a header with a real timestamp and placeholder length/CRC.

    ``payload_length`` and ``crc32`` are filled in by :meth:`Packet.encode`
    from the actual payload, so callers pass ``0`` for both here.

    Args:
        packet_type: The type of packet this header describes.
        message_id: Unique ID for request/response correlation.
        flags: Optional bitfield (compression, encryption, etc.).

    Returns:
        A :class:`PacketHeader` ready to pair with a payload in a :class:`Packet`.
    """
    return PacketHeader(
        version=CURRENT_VERSION,
        packet_type=packet_type,
        flags=flags,
        message_id=message_id,
        payload_length=0,
        timestamp=int(time.time() * 1000),
        crc32=0,
    )
