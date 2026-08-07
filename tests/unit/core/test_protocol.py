"""Unit tests for the wire protocol."""

import pytest

from securesync.core.protocol import (
    InvalidHeaderError,
    Packet,
    PacketHeader,
    PacketType,
    PayloadIntegrityError,
    make_header,
)


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
    with pytest.raises(InvalidHeaderError, match="Invalid magic number"):
        PacketHeader.unpack(bytes(bad_data))


def test_unpack_invalid_size() -> None:
    with pytest.raises(InvalidHeaderError, match="Invalid header size"):
        PacketHeader.unpack(b"too short")


class TestPacketEncodeDecode:
    """Tests for `Packet.encode`/`Packet.decode` round-tripping and integrity."""

    def test_round_trip_preserves_payload_and_type(self) -> None:
        header = make_header(PacketType.CHUNK_DATA, message_id=7)
        packet = Packet(header=header, payload={"chunk_id": "abc123", "index": 4})

        decoded = Packet.decode(packet.encode())

        assert decoded.payload == packet.payload
        assert decoded.header.packet_type == PacketType.CHUNK_DATA
        assert decoded.header.message_id == 7

    def test_encode_computes_real_payload_length_and_crc(self) -> None:
        """`encode` fills in `payload_length`/`crc32` even if the header had 0."""
        header = make_header(PacketType.HELLO, message_id=1)
        assert header.payload_length == 0
        assert header.crc32 == 0

        encoded = Packet(header=header, payload={"a": 1}).encode()

        decoded_header = PacketHeader.unpack(encoded[:32])
        assert decoded_header.payload_length > 0
        assert decoded_header.crc32 != 0

    def test_decode_rejects_tampered_payload(self) -> None:
        """A single flipped byte in the payload fails CRC verification."""
        encoded = bytearray(
            Packet(header=make_header(PacketType.HELLO, message_id=1), payload={"a": 1}).encode()
        )
        encoded[-1] ^= 0xFF

        with pytest.raises(PayloadIntegrityError):
            Packet.decode(bytes(encoded))

    def test_decode_rejects_truncated_payload(self) -> None:
        """A payload shorter than `header.payload_length` claims is rejected."""
        encoded = Packet(
            header=make_header(PacketType.HELLO, message_id=1), payload={"a": 1}
        ).encode()

        with pytest.raises(PayloadIntegrityError):
            Packet.decode(encoded[:-1])
