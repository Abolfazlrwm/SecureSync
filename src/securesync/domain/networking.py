"""Domain entities and ports for networking and peer discovery.

This module defines the abstractions for peer management and discovery,
isolated from concrete network protocols (UDP, mDNS) and storage
technologies.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, unique
from typing import Protocol, runtime_checkable


@unique
class PeerStatus(StrEnum):
    """The current known connectivity state of a peer."""

    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    """The stable identity of a peer device.

    Attributes:
        device_id: A unique, stable identifier for the device (e.g. a UUID).
        hostname: The human-readable hostname of the device.
        fingerprint: A short, human-verifiable hash of the peer's public key.
    """

    device_id: str
    hostname: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class PeerAddress:
    """The network location of a peer.

    Attributes:
        ip_address: The IPv4 or IPv6 address.
        port: The TCP port SecureSync is listening on.
    """

    ip_address: str
    port: int


@dataclass(frozen=True, slots=True)
class PeerCapabilities:
    """Features and versions supported by a peer.

    Attributes:
        version: The protocol version string.
        features: A set of supported feature flags (e.g. "compression").
    """

    version: str
    features: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class Peer:
    """A discovered or known peer device.

    Attributes:
        identity: Stable identity information.
        address: Current network location.
        capabilities: Supported protocol and features.
        status: Current connectivity state.
        last_seen: The UTC instant the peer was last heard from.
    """

    identity: PeerIdentity
    address: PeerAddress
    capabilities: PeerCapabilities
    status: PeerStatus = PeerStatus.UNKNOWN
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def device_id(self) -> str:
        """Helper to get the device ID directly."""
        return self.identity.device_id


class PeerRepository(ABC):
    """Port for persisting and retrieving known peers."""

    @abstractmethod
    async def save(self, peer: Peer) -> None:
        """Save or update a peer in the repository."""
        raise NotImplementedError

    @abstractmethod
    async def get_by_id(self, device_id: str) -> Peer | None:
        """Retrieve a peer by its unique device ID."""
        raise NotImplementedError

    @abstractmethod
    async def list_all(self) -> list[Peer]:
        """List all known peers."""
        raise NotImplementedError

    @abstractmethod
    async def remove(self, device_id: str) -> None:
        """Remove a peer from the repository."""
        raise NotImplementedError


@runtime_checkable
class PeerDiscoveryObserver(Protocol):
    """Observer for peer discovery events."""

    async def on_peer_discovered(self, peer: Peer) -> None:
        """Handle a newly discovered or updated peer."""
        ...

    async def on_peer_lost(self, device_id: str) -> None:
        """Handle a peer that is no longer reachable."""
        ...


class DiscoveryService(ABC):
    """Port for discovering peers on the local network."""

    @abstractmethod
    async def start(self) -> None:
        """Start the discovery process."""
        raise NotImplementedError

    @abstractmethod
    async def stop(self) -> None:
        """Stop the discovery process."""
        raise NotImplementedError

    @abstractmethod
    def subscribe(self, observer: PeerDiscoveryObserver) -> None:
        """Register an observer for discovery events."""
        raise NotImplementedError

    @abstractmethod
    def unsubscribe(self, observer: PeerDiscoveryObserver) -> None:
        """Unregister an observer."""
        raise NotImplementedError

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """Whether the discovery service is active."""
        raise NotImplementedError
