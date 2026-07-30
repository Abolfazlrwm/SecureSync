"""mDNS-based implementation of the DiscoveryService port using zeroconf."""

from __future__ import annotations

import asyncio
import socket
from typing import Final

from zeroconf import (
    IPVersion,
    ServiceBrowser,
    ServiceInfo,
    ServiceListener,
    Zeroconf,
)

from securesync.domain.networking import (
    DiscoveryService,
    Peer,
    PeerAddress,
    PeerCapabilities,
    PeerDiscoveryObserver,
    PeerIdentity,
    PeerStatus,
)

SERVICE_TYPE: Final = "_securesync._tcp.local."


class MdnsDiscoveryService(DiscoveryService, ServiceListener):
    """mDNS implementation of Peer Discovery.

    Uses the ``zeroconf`` library to advertise the local SecureSync
    instance and browse for others on the local network.
    """

    def __init__(
        self,
        device_id: str,
        hostname: str,
        fingerprint: str,
        port: int,
        version: str = "0.1.0",
    ) -> None:
        """Initialize the discovery service.

        Args:
            device_id: This device's unique ID.
            hostname: This device's hostname.
            fingerprint: This device's public key fingerprint.
            port: The port this device is listening on for sync.
            version: The protocol version.
        """
        self._device_id = device_id
        self._hostname = hostname
        self._fingerprint = fingerprint
        self._port = port
        self._version = version

        self._zeroconf: Zeroconf | None = None
        self._browser: ServiceBrowser | None = None
        self._observers: list[PeerDiscoveryObserver] = []
        self._running = False
        self._lock = asyncio.Lock()

    def subscribe(self, observer: PeerDiscoveryObserver) -> None:
        """See :meth:`DiscoveryService.subscribe`."""
        if observer not in self._observers:
            self._observers.append(observer)

    def unsubscribe(self, observer: PeerDiscoveryObserver) -> None:
        """See :meth:`DiscoveryService.unsubscribe`."""
        if observer in self._observers:
            self._observers.remove(observer)

    @property
    def is_running(self) -> bool:
        """See :meth:`DiscoveryService.is_running`."""
        return self._running

    async def start(self) -> None:
        """See :meth:`DiscoveryService.start`."""
        async with self._lock:
            if self._running:
                return

            self._zeroconf = Zeroconf(ip_version=IPVersion.V4Only)

            # Advertise ourselves
            info = ServiceInfo(
                SERVICE_TYPE,
                f"{self._device_id}.{SERVICE_TYPE}",
                addresses=[socket.inet_aton("0.0.0.0")],  # Will be filled by zeroconf
                port=self._port,
                properties={
                    b"device_id": self._device_id.encode(),
                    b"hostname": self._hostname.encode(),
                    b"fingerprint": self._fingerprint.encode(),
                    b"version": self._version.encode(),
                },
                server=f"{self._hostname}.local.",
            )
            self._zeroconf.register_service(info)

            # Browse for others
            self._browser = ServiceBrowser(self._zeroconf, SERVICE_TYPE, self)
            self._running = True

    async def stop(self) -> None:
        """See :meth:`DiscoveryService.stop`."""
        async with self._lock:
            if not self._running:
                return

            if self._zeroconf:
                self._zeroconf.unregister_all_services()
                self._zeroconf.close()

            self._zeroconf = None
            self._browser = None
            self._running = False

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Callback from zeroconf when a new service is found."""
        info = zc.get_service_info(type_, name)
        if info:
            asyncio.run_coroutine_threadsafe(
                self._handle_discovered_service(info), asyncio.get_running_loop()
            )

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Callback from zeroconf when a service is lost."""
        # zeroconf name is usually "device_id._securesync._tcp.local."
        device_id = name.split(".")[0]
        for observer in self._observers:
            asyncio.run_coroutine_threadsafe(
                observer.on_peer_lost(device_id), asyncio.get_running_loop()
            )

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Callback from zeroconf when a service is updated."""
        self.add_service(zc, type_, name)

    async def _handle_discovered_service(self, info: ServiceInfo) -> None:
        """Translate zeroconf ServiceInfo to domain Peer and notify observers."""
        props = info.properties
        try:
            device_id_bytes = props.get(b"device_id")
            if not device_id_bytes:
                return
            device_id = device_id_bytes.decode()

            # Don't discover ourselves
            if device_id == self._device_id:
                return

            hostname_bytes = props.get(b"hostname")
            fingerprint_bytes = props.get(b"fingerprint")
            version_bytes = props.get(b"version")

            if not (hostname_bytes and fingerprint_bytes and version_bytes and info.port):
                return

            peer = Peer(
                identity=PeerIdentity(
                    device_id=device_id,
                    hostname=hostname_bytes.decode(),
                    fingerprint=fingerprint_bytes.decode(),
                ),
                address=PeerAddress(
                    ip_address=socket.inet_ntoa(info.addresses[0]),
                    port=info.port,
                ),
                capabilities=PeerCapabilities(
                    version=version_bytes.decode(),
                ),
                status=PeerStatus.ONLINE,
            )

            for observer in self._observers:
                await observer.on_peer_discovered(peer)
        except (KeyError, IndexError, UnicodeDecodeError):
            # Skip invalid or malformed service advertisements
            pass
