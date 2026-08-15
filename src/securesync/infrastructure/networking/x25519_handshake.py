"""Real X25519 key-exchange handshake over TCP, authenticated with Ed25519.

This resolves the exact ambiguity flagged in
:meth:`~securesync.infrastructure.crypto.pyca_crypto.PycaSessionKeyProvider.derive_session_keys`'s
docstring: two peers deriving keys from the same shared secret and
salt get an *identical* ``(key_1, key_2)`` pair — without a role
convention, both would end up trying to encrypt with the same key.
:class:`X25519Handshake` fixes the role deterministically: the
initiator (the side that opened the connection) uses
``(send=key_1, receive=key_2)``; the responder (the side that
accepted it) uses the swapped ``(send=key_2, receive=key_1)`` — so
the initiator's send key is always the responder's receive key, and
vice versa.

Each side also signs its ephemeral public key (bound to the
handshake's salt) with its long-term Ed25519 identity, and the
receiving side checks that signature and pins the identity's public
key via :class:`~securesync.domain.identity.TrustedPeerRepository`
(trust-on-first-use) — see
``docs/adr/0019-peer-authentication-and-trust-on-first-use.md`` for
what this does and doesn't protect against.
"""

from __future__ import annotations

import asyncio
import os
import struct
from typing import Any

import msgpack  # type: ignore[import-untyped]
import structlog

from securesync.domain.crypto import KeyExchangeProvider, SessionKeyProvider
from securesync.domain.identity import IdentityKeyPair, IdentityProvider, TrustedPeerRepository
from securesync.domain.identity_exceptions import (
    InvalidHandshakeSignatureError,
    PeerIdentityMismatchError,
)

logger = structlog.get_logger(__name__)

_SALT_SIZE = 16
_LENGTH_PREFIX_FORMAT = ">I"
_LENGTH_PREFIX_SIZE = struct.calcsize(_LENGTH_PREFIX_FORMAT)


class HandshakeResult:
    """The outcome of a completed handshake.

    Attributes:
        peer_device_id: The device ID the other side identified itself as.
        send_key: Key to encrypt messages sent to this peer.
        receive_key: Key to decrypt messages received from this peer.
        peer_transfer_port: The port the peer's chunk-transfer
            transport listens on, exchanged as part of this handshake.
    """

    __slots__ = ("peer_device_id", "send_key", "receive_key", "peer_transfer_port")

    def __init__(
        self,
        peer_device_id: str,
        send_key: bytes,
        receive_key: bytes,
        peer_transfer_port: int,
    ) -> None:
        """Initialize the result.

        Args:
            peer_device_id: The device ID the other side identified itself as.
            send_key: Key to encrypt messages sent to this peer.
            receive_key: Key to decrypt messages received from this peer.
            peer_transfer_port: The port the peer's chunk-transfer
                transport listens on.
        """
        self.peer_device_id = peer_device_id
        self.send_key = send_key
        self.receive_key = receive_key
        self.peer_transfer_port = peer_transfer_port


class X25519Handshake:
    """Performs the initiator or responder half of an X25519 key exchange."""

    def __init__(
        self,
        own_device_id: str,
        own_transfer_port: int,
        key_exchange: KeyExchangeProvider,
        session_keys: SessionKeyProvider,
        identity_provider: IdentityProvider,
        own_identity: IdentityKeyPair,
        trusted_peers: TrustedPeerRepository,
    ) -> None:
        """Initialize the handshake.

        Args:
            own_device_id: This device's ID, sent to the peer so it
                knows who it's negotiating keys with.
            own_transfer_port: This device's chunk-transfer port,
                sent to the peer so it knows where to reach the
                resulting `TcpTransferTransport`.
            key_exchange: Generates ephemeral keypairs and derives the
                ECDH shared secret.
            session_keys: Derives the final `(key_1, key_2)` pair from
                the shared secret.
            identity_provider: Signs outgoing handshake messages and
                verifies incoming ones.
            own_identity: This device's long-term Ed25519 identity keypair.
            trusted_peers: Pins and checks the peer's long-term public
                key across handshakes (trust-on-first-use).
        """
        self._own_device_id = own_device_id
        self._own_transfer_port = own_transfer_port
        self._key_exchange = key_exchange
        self._session_keys = session_keys
        self._identity_provider = identity_provider
        self._own_identity = own_identity
        self._trusted_peers = trusted_peers

    async def initiate(self, host: str, port: int) -> HandshakeResult:
        """Connect to a peer's handshake port and negotiate keys as the initiator.

        Args:
            host: The peer's handshake host.
            port: The peer's handshake port.

        Returns:
            The negotiated `HandshakeResult`.

        Raises:
            OSError: If the connection can't be established.
            InvalidHandshakeSignatureError: If the peer's reply doesn't
                verify against its claimed identity key.
            PeerIdentityMismatchError: If the peer's claimed identity
                key differs from the one previously trusted for its
                device ID.
        """
        private_key, public_key = self._key_exchange.generate_key_pair()
        salt = os.urandom(_SALT_SIZE)
        signature = self._identity_provider.sign(self._own_identity.private_key, salt + public_key)

        reader, writer = await asyncio.open_connection(host, port)
        try:
            await self._write_message(
                writer,
                {
                    "device_id": self._own_device_id,
                    "transfer_port": self._own_transfer_port,
                    "salt": salt,
                    "public_key": public_key,
                    "identity_public_key": self._own_identity.public_key,
                    "signature": signature,
                },
            )
            response = await self._read_message(reader)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

        await self._verify_and_trust(response, salt + response["public_key"])

        shared_secret = self._key_exchange.derive_shared_secret(
            private_key, response["public_key"]
        )
        key_1, key_2 = self._session_keys.derive_session_keys(shared_secret, salt)
        logger.info("handshake_completed_as_initiator", peer_device_id=response["device_id"])
        return HandshakeResult(
            peer_device_id=response["device_id"],
            send_key=key_1,
            receive_key=key_2,
            peer_transfer_port=response["transfer_port"],
        )

    async def accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> HandshakeResult:
        """Handle one inbound handshake connection as the responder.

        Args:
            reader: The inbound connection's stream reader.
            writer: The inbound connection's stream writer.

        Returns:
            The negotiated `HandshakeResult`.

        Raises:
            InvalidHandshakeSignatureError: If the initiator's request
                doesn't verify against its claimed identity key.
            PeerIdentityMismatchError: If the initiator's claimed
                identity key differs from the one previously trusted
                for its device ID.
        """
        request = await self._read_message(reader)
        await self._verify_and_trust(request, request["salt"] + request["public_key"])

        private_key, public_key = self._key_exchange.generate_key_pair()
        signature = self._identity_provider.sign(
            self._own_identity.private_key, request["salt"] + public_key
        )
        await self._write_message(
            writer,
            {
                "device_id": self._own_device_id,
                "transfer_port": self._own_transfer_port,
                "public_key": public_key,
                "identity_public_key": self._own_identity.public_key,
                "signature": signature,
            },
        )

        shared_secret = self._key_exchange.derive_shared_secret(
            private_key, request["public_key"]
        )
        key_1, key_2 = self._session_keys.derive_session_keys(shared_secret, request["salt"])
        logger.info("handshake_completed_as_responder", peer_device_id=request["device_id"])
        # Responder: swapped relative to the initiator, so each side's
        # send_key equals the other side's receive_key.
        return HandshakeResult(
            peer_device_id=request["device_id"],
            send_key=key_2,
            receive_key=key_1,
            peer_transfer_port=request["transfer_port"],
        )

    async def _verify_and_trust(self, message: dict[str, Any], signed_data: bytes) -> None:
        """Verify a handshake message's signature and enforce trust-on-first-use.

        Args:
            message: The decoded handshake message, containing at
                least ``device_id``, ``identity_public_key``, and
                ``signature``.
            signed_data: The exact bytes the sender should have signed.

        Raises:
            InvalidHandshakeSignatureError: If the signature doesn't
                verify against the claimed identity key.
            PeerIdentityMismatchError: If a different key was
                previously trusted for this device ID.
        """
        identity_public_key = message["identity_public_key"]
        if not self._identity_provider.verify(
            identity_public_key, signed_data, message["signature"]
        ):
            raise InvalidHandshakeSignatureError(
                f"signature from {message['device_id']!r} does not verify"
            )

        device_id = message["device_id"]
        trusted_key = await self._trusted_peers.get_trusted_key(device_id)
        if trusted_key is not None and trusted_key != identity_public_key:
            raise PeerIdentityMismatchError(
                f"{device_id!r} presented a different identity key than previously trusted"
            )
        await self._trusted_peers.trust(device_id, identity_public_key)

    @staticmethod
    async def _write_message(writer: asyncio.StreamWriter, message: dict[str, Any]) -> None:
        """Write a length-prefixed, msgpack-encoded handshake message."""
        data = msgpack.packb(message)
        writer.write(struct.pack(_LENGTH_PREFIX_FORMAT, len(data)) + data)
        await writer.drain()

    @staticmethod
    async def _read_message(reader: asyncio.StreamReader) -> dict[str, Any]:
        """Read and decode a length-prefixed, msgpack-encoded handshake message."""
        length_bytes = await reader.readexactly(_LENGTH_PREFIX_SIZE)
        (length,) = struct.unpack(_LENGTH_PREFIX_FORMAT, length_bytes)
        data = await reader.readexactly(length)
        result: dict[str, Any] = msgpack.unpackb(data, raw=False)
        return result


class HandshakeServer:
    """Accepts inbound handshake connections and publishes their results.

    A thin `asyncio.start_server` wrapper: each inbound connection runs
    :meth:`X25519Handshake.accept` and the resulting `HandshakeResult`
    is pushed onto :attr:`results`, for a caller to drain and use to
    construct a per-peer
    :class:`~securesync.infrastructure.networking.tcp_transport.TcpTransferTransport`.
    """

    def __init__(self, handshake: X25519Handshake) -> None:
        """Initialize the server.

        Args:
            handshake: Performs the responder side of each inbound handshake.
        """
        self._handshake = handshake
        self._server: asyncio.Server | None = None
        self.results: asyncio.Queue[HandshakeResult] = asyncio.Queue()

    async def start(self, host: str, port: int) -> None:
        """Start accepting inbound handshake connections.

        Args:
            host: Host/interface to accept connections on.
            port: Port to accept connections on.

        Raises:
            OSError: If `port` can't be bound.
        """
        self._server = await asyncio.start_server(self._handle_connection, host, port)

    async def stop(self) -> None:
        """Stop accepting inbound handshake connections."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            result = await self._handshake.accept(reader, writer)
            await self.results.put(result)
        except (
            asyncio.IncompleteReadError,
            ConnectionError,
            KeyError,
            InvalidHandshakeSignatureError,
            PeerIdentityMismatchError,
        ) as e:
            logger.warning("handshake_failed", error=str(e), error_type=type(e).__name__)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
