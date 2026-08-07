"""Unit tests for networking domain entities."""

from datetime import datetime

from securesync.domain.networking import (
    Peer,
    PeerAddress,
    PeerCapabilities,
    PeerIdentity,
    PeerStatus,
)


def test_peer_identity_creation() -> None:
    identity = PeerIdentity(
        device_id="dev-123",
        hostname="test-host",
        fingerprint="fp-456",
    )
    assert identity.device_id == "dev-123"
    assert identity.hostname == "test-host"
    assert identity.fingerprint == "fp-456"


def test_peer_address_creation() -> None:
    address = PeerAddress(ip_address="127.0.0.1", port=8080)
    assert address.ip_address == "127.0.0.1"
    assert address.port == 8080


def test_peer_creation_defaults() -> None:
    identity = PeerIdentity("d1", "h1", "f1")
    address = PeerAddress("1.1.1.1", 1111)
    capabilities = PeerCapabilities("1.0")

    peer = Peer(identity, address, capabilities)

    assert peer.identity == identity
    assert peer.address == address
    assert peer.capabilities == capabilities
    assert peer.status == PeerStatus.UNKNOWN
    assert isinstance(peer.last_seen, datetime)
    assert peer.device_id == "d1"
