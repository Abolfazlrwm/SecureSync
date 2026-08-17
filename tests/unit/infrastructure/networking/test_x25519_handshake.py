"""Unit tests for X25519Handshake, HandshakeServer, and peer authentication."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from securesync.infrastructure.crypto.ed25519_identity_provider import Ed25519IdentityProvider
from securesync.infrastructure.crypto.pyca_crypto import (
    PycaKeyExchangeProvider,
    PycaSessionKeyProvider,
)
from securesync.infrastructure.networking.file_trusted_peer_repository import (
    FileTrustedPeerRepository,
)
from securesync.infrastructure.networking.x25519_handshake import (
    HandshakeServer,
    X25519Handshake,
)


def _handshake(device_id: str, storage_dir: Path) -> X25519Handshake:
    identity_provider = Ed25519IdentityProvider(storage_dir)
    own_identity = identity_provider.load_or_create()
    trusted_peers = FileTrustedPeerRepository(storage_dir / "trust.json")
    return X25519Handshake(
        device_id,
        9999,  # dummy transfer_port — not exercised by these handshake-only tests
        9998,  # dummy manifest_port — not exercised by these handshake-only tests
        PycaKeyExchangeProvider(),
        PycaSessionKeyProvider(),
        identity_provider,
        own_identity,
        trusted_peers,
    )


class TestHandshake:
    """Tests for a real initiator/responder handshake over a real socket."""

    async def test_initiator_and_responder_agree_on_peer_identity(self, tmp_path: Path) -> None:
        server = HandshakeServer(_handshake("dev-b", tmp_path / "b"))
        await server.start("127.0.0.1", 19701)
        try:
            initiator = _handshake("dev-a", tmp_path / "a")
            a_result = await initiator.initiate("127.0.0.1", 19701)
            b_result = await asyncio.wait_for(server.results.get(), timeout=2)

            assert a_result.peer_device_id == "dev-b"
            assert b_result.peer_device_id == "dev-a"
        finally:
            await server.stop()

    async def test_send_and_receive_keys_are_correctly_swapped(self, tmp_path: Path) -> None:
        """The initiator's send key must equal the responder's receive key, and vice versa."""
        server = HandshakeServer(_handshake("dev-b", tmp_path / "b"))
        await server.start("127.0.0.1", 19702)
        try:
            initiator = _handshake("dev-a", tmp_path / "a")
            a_result = await initiator.initiate("127.0.0.1", 19702)
            b_result = await asyncio.wait_for(server.results.get(), timeout=2)

            assert a_result.send_key == b_result.receive_key
            assert a_result.receive_key == b_result.send_key
        finally:
            await server.stop()

    async def test_send_and_receive_keys_differ(self, tmp_path: Path) -> None:
        """Each side gets two distinct keys, not the same key reused both ways."""
        server = HandshakeServer(_handshake("dev-b", tmp_path / "b"))
        await server.start("127.0.0.1", 19703)
        try:
            initiator = _handshake("dev-a", tmp_path / "a")
            a_result = await initiator.initiate("127.0.0.1", 19703)

            assert a_result.send_key != a_result.receive_key
        finally:
            await server.stop()

    async def test_repeated_handshakes_produce_different_keys(self, tmp_path: Path) -> None:
        """Each handshake uses a fresh ephemeral keypair and salt, so keys never repeat."""
        responder = _handshake("dev-b", tmp_path / "b")
        server = HandshakeServer(responder)
        await server.start("127.0.0.1", 19704)
        try:
            initiator = _handshake("dev-a", tmp_path / "a")
            first = await initiator.initiate("127.0.0.1", 19704)
            await server.results.get()
            second = await initiator.initiate("127.0.0.1", 19704)
            await server.results.get()

            assert first.send_key != second.send_key
        finally:
            await server.stop()


class TestPeerAuthentication:
    """Tests for signature verification and trust-on-first-use enforcement."""

    async def test_first_handshake_pins_the_peers_identity_key(self, tmp_path: Path) -> None:
        server = HandshakeServer(_handshake("dev-b", tmp_path / "b"))
        await server.start("127.0.0.1", 19705)
        try:
            initiator = _handshake("dev-a", tmp_path / "a")
            await initiator.initiate("127.0.0.1", 19705)
            await server.results.get()

            trust_store = FileTrustedPeerRepository(tmp_path / "b" / "trust.json")
            identity_a = Ed25519IdentityProvider(tmp_path / "a").load_or_create()
            pinned = await trust_store.get_trusted_key("dev-a")

            assert pinned == identity_a.public_key
        finally:
            await server.stop()

    async def test_repeat_handshake_with_same_identity_succeeds(self, tmp_path: Path) -> None:
        responder = _handshake("dev-b", tmp_path / "b")
        server = HandshakeServer(responder)
        await server.start("127.0.0.1", 19706)
        try:
            initiator = _handshake("dev-a", tmp_path / "a")
            await initiator.initiate("127.0.0.1", 19706)
            await server.results.get()

            # Second handshake, same on-disk identity for "dev-a".
            second_result = await initiator.initiate("127.0.0.1", 19706)
            await server.results.get()

            assert second_result.peer_device_id == "dev-b"
        finally:
            await server.stop()

    async def test_impostor_with_different_identity_is_rejected(self, tmp_path: Path) -> None:
        """A second party claiming the same device_id but a different key is refused."""
        responder = _handshake("dev-b", tmp_path / "b")
        server = HandshakeServer(responder)
        await server.start("127.0.0.1", 19707)
        try:
            # Real "dev-a" handshakes first, pinning its key.
            real_initiator = _handshake("dev-a", tmp_path / "a")
            await real_initiator.initiate("127.0.0.1", 19707)
            await server.results.get()

            # An impostor with a DIFFERENT identity claims to be "dev-a".
            impostor = _handshake("dev-a", tmp_path / "impostor")
            with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
                await impostor.initiate("127.0.0.1", 19707)

            # The responder must not have published a result for the impostor.
            await asyncio.sleep(0.05)
            assert server.results.empty()
        finally:
            await server.stop()
