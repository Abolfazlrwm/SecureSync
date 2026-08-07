"""Unit tests for MdnsDiscoveryService."""

from unittest.mock import MagicMock, patch

import pytest

from securesync.infrastructure.networking.mdns_discovery import MdnsDiscoveryService


@pytest.mark.asyncio
async def test_mdns_discovery_start_stop() -> None:
    # Patch Zeroconf and ServiceBrowser to avoid real network calls
    with (
        patch("securesync.infrastructure.networking.mdns_discovery.Zeroconf") as mock_zc,
        patch("securesync.infrastructure.networking.mdns_discovery.ServiceBrowser") as mock_browser,
    ):

        service = MdnsDiscoveryService("d1", "h1", "f1", 8080)

        await service.start()
        assert service.is_running
        mock_zc.return_value.register_service.assert_called_once()
        mock_browser.assert_called_once()

        await service.stop()
        assert not service.is_running
        mock_zc.return_value.unregister_all_services.assert_called_once()
        mock_zc.return_value.close.assert_called_once()


def test_mdns_discovery_subscription() -> None:
    service = MdnsDiscoveryService("d1", "h1", "f1", 8080)
    observer = MagicMock()

    service.subscribe(observer)
    assert observer in service._observers

    service.unsubscribe(observer)
    assert observer not in service._observers
