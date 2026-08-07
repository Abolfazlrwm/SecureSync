"""Binary wire protocol for SecureSync.

Defines the header layout, packet types, and serialization logic for
peer-to-peer communication.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
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
        """Deserialize a 32-byte header."""
        if len(data) != HEADER_SIZE:
            raise ValueError(f"Invalid header size: {len(data)}")

        magic, version, p_type, flags, msg_id, p_len, ts, crc = struct.unpack(">IBBHQIQI", data)

        if magic != MAGIC:
            raise ValueError(f"Invalid magic number: {hex(magic)}")

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
        """Encode the packet to binary."""
        payload_bytes: bytes = msgpack.packb(self.payload)
        # Update header with actual payload length and CRC
        # In a real implementation, CRC would be calculated here
        return self.header.pack() + payload_bytes
