"""Unit tests for the wire protocol."""

import pytest

from securesync.core.protocol import PacketHeader, PacketType


def test_packet_header_packing_unpacking() -> None:
    header = PacketHeader(
        version=1,
        packet_type=PacketType.HELLO,
        flags=0x01,
        message_id=12345,
        payload_length=100,
        timestamp=1600000000,
        crc32=0xDEADBEEF,
    )

    packed = header.pack()
    assert len(packed) == 32

    unpacked = PacketHeader.unpack(packed)
    assert unpacked == header


def test_unpack_invalid_magic() -> None:
    bad_data = bytearray(32)
    # Leave magic as 0
    with pytest.raises(ValueError, match="Invalid magic number"):
        PacketHeader.unpack(bytes(bad_data))


def test_unpack_invalid_size() -> None:
    with pytest.raises(ValueError, match="Invalid header size"):
        PacketHeader.unpack(b"too short")
