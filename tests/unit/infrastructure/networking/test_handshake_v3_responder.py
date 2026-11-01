"""Tests for the v3 responder state machine (design §6.2).

The happy path runs the real initiator against the real responder, which is the
strongest statement available: two independent halves agree on the transcript,
the keys and the session id. The failure paths are driven by
:class:`tests.support.v3_raw_client.RawInitiator`, which can corrupt one message
at a time.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from securesync.domain.identity import IdentityKeyPair
from securesync.domain.identity_exceptions import (
    InvalidHandshakeSignatureError,
    PeerIdentityMismatchError,
)
from securesync.infrastructure.crypto.ed25519_identity_provider import Ed25519IdentityProvider
from securesync.infrastructure.crypto.pyca_crypto import PycaKeyExchangeProvider
from securesync.infrastructure.networking.handshake_keys import KeyConfirmationError
from securesync.infrastructure.networking.handshake_messages import (
    STATUS_ACCEPT,
    STATUS_REJECT,
    HandshakeValidationError,
)
from securesync.infrastructure.networking.handshake_rate_limit import GlobalHandshakeLimiter
from securesync.infrastructure.networking.handshake_v3 import (
    HandshakeBusyError,
    HandshakeDeadlineError,
    HandshakeRateLimitedError,
    HandshakeV3,
)
from securesync.infrastructure.networking.replay_protection import (
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    UnsupportedVersionError,
)
from securesync.infrastructure.networking.session_store import SessionIdCollisionError
from tests.doubles import FakeTrustedPeerRepository
from tests.support.v3_raw_client import RawInitiator

INITIATOR_ID = "device-alpha"
RESPONDER_ID = "device-beta"


def _identity() -> IdentityKeyPair:
    private = Ed25519PrivateKey.generate()
    return IdentityKeyPair(
        private_key=private.private_bytes_raw(),
        public_key=private.public_key().public_bytes_raw(),
    )


@asynccontextmanager
async def responder_server(
    handshake: HandshakeV3,
    *,
    on_confirmed: object = None,
) -> AsyncIterator[tuple[int, list[BaseException], list[object]]]:
    """Serve ``handshake.accept`` on an ephemeral port, collecting outcomes."""
    errors: list[BaseException] = []
    results: list[object] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            results.append(
                await handshake.accept(reader, writer, on_confirmed=on_confirmed)  # type: ignore[arg-type]
            )
        except BaseException as exc:
            errors.append(exc)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    assert isinstance(port, int)
    try:
        yield port, errors, results
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()


async def _wait_until(predicate: object, wait_seconds: float = 2.0) -> None:
    """Poll ``predicate`` until it is true, or fail the test."""
    deadline = asyncio.get_running_loop().time() + wait_seconds
    while asyncio.get_running_loop().time() < deadline:
        if predicate():  # type: ignore[operator]
            return
        await asyncio.sleep(0.005)
    raise AssertionError("condition not met in time")


@pytest.fixture
def identity_provider(tmp_path: Path) -> Ed25519IdentityProvider:
    return Ed25519IdentityProvider(tmp_path / "identity")


@pytest.fixture
def key_exchange() -> PycaKeyExchangeProvider:
    return PycaKeyExchangeProvider()


@pytest.fixture
def responder_identity() -> IdentityKeyPair:
    return _identity()


@pytest.fixture
def responder_trust() -> FakeTrustedPeerRepository:
    return FakeTrustedPeerRepository()


@pytest.fixture
def initiator_trust() -> FakeTrustedPeerRepository:
    return FakeTrustedPeerRepository()


def _responder(
    *,
    own_identity: IdentityKeyPair,
    identity_provider: Ed25519IdentityProvider,
    key_exchange: PycaKeyExchangeProvider,
    trusted_peers: FakeTrustedPeerRepository,
    deadline: float = 10.0,
    max_half_open: int = 64,
    global_limiter: GlobalHandshakeLimiter | None = None,
) -> HandshakeV3:
    return HandshakeV3(
        RESPONDER_ID,
        5001,
        5002,
        key_exchange,
        identity_provider,
        own_identity,
        trusted_peers,
        deadline=deadline,
        max_half_open=max_half_open,
        global_limiter=global_limiter,
    )


def _initiator(
    *,
    own_identity: IdentityKeyPair,
    identity_provider: Ed25519IdentityProvider,
    key_exchange: PycaKeyExchangeProvider,
    trusted_peers: FakeTrustedPeerRepository,
) -> HandshakeV3:
    return HandshakeV3(
        INITIATOR_ID,
        5000,
        5001,
        key_exchange,
        identity_provider,
        own_identity,
        trusted_peers,
    )


class TestRealPair:
    async def test_both_halves_agree_on_the_session(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
        initiator_trust: FakeTrustedPeerRepository,
    ) -> None:
        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
        )
        async with responder_server(responder) as (port, errors, results):
            initiator_result = await _initiator(
                own_identity=_identity(),
                identity_provider=identity_provider,
                key_exchange=key_exchange,
                trusted_peers=initiator_trust,
            ).initiate("127.0.0.1", port)
            await _wait_until(lambda: results or errors)

        assert not errors
        responder_result = results[0]
        assert responder_result.peer_device_id == INITIATOR_ID  # type: ignore[attr-defined]
        assert responder_result.role == ROLE_RESPONDER  # type: ignore[attr-defined]
        assert initiator_result.role == ROLE_INITIATOR
        assert responder_result.session_id == initiator_result.session_id  # type: ignore[attr-defined]
        # Mirror keys: what one sends is what the other receives.
        assert responder_result.receive_key == initiator_result.send_key  # type: ignore[attr-defined]
        assert responder_result.send_key == initiator_result.receive_key  # type: ignore[attr-defined]
        assert initiator_result.peer_transfer_port == 5001
        assert initiator_result.peer_manifest_port == 5002

    async def test_both_sides_pin_each_other(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
        initiator_trust: FakeTrustedPeerRepository,
    ) -> None:
        initiator_identity = _identity()
        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
        )
        async with responder_server(responder) as (port, errors, results):
            await _initiator(
                own_identity=initiator_identity,
                identity_provider=identity_provider,
                key_exchange=key_exchange,
                trusted_peers=initiator_trust,
            ).initiate("127.0.0.1", port)
            await _wait_until(lambda: results or errors)

        assert not errors
        assert await initiator_trust.get_trusted_key(RESPONDER_ID) == responder_identity.public_key
        assert await responder_trust.get_trusted_key(INITIATOR_ID) == initiator_identity.public_key

    async def test_the_session_is_recorded_before_message_4(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
        initiator_trust: FakeTrustedPeerRepository,
    ) -> None:
        # The race amendment 1 exists for: the callback must have run while the
        # initiator is still blocked waiting for message 4.
        observed: dict[str, bool] = {}
        initiator_returned = {"value": False}

        def on_confirmed(_result: object) -> None:
            observed["initiator_had_returned"] = initiator_returned["value"]

        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
        )
        async with responder_server(responder, on_confirmed=on_confirmed) as (
            port,
            errors,
            results,
        ):
            await _initiator(
                own_identity=_identity(),
                identity_provider=identity_provider,
                key_exchange=key_exchange,
                trusted_peers=initiator_trust,
            ).initiate("127.0.0.1", port)
            initiator_returned["value"] = True
            await _wait_until(lambda: results or errors)

        assert not errors
        assert observed == {"initiator_had_returned": False}


class TestMessageValidation:
    async def test_a_v2_hello_gets_no_reply(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
    ) -> None:
        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
        )
        async with responder_server(responder) as (port, errors, _results):
            client = await RawInitiator.connect(
                "127.0.0.1",
                port,
                key_exchange=key_exchange,
                identity_provider=identity_provider,
                own_identity=_identity(),
            )
            # A v2 peer's first byte is a msgpack type, not a version.
            await client.send_raw(b"\x02\x01" + b"\x00" * 100)
            with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
                await client.read_raw()
            await client.close()
            await _wait_until(lambda: errors)

        assert isinstance(errors[0], UnsupportedVersionError)
        assert await responder_trust.get_trusted_key(INITIATOR_ID) is None

    async def test_a_peer_claiming_our_device_id_is_refused(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
    ) -> None:
        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
        )
        async with responder_server(responder) as (port, errors, _results):
            client = await RawInitiator.connect(
                "127.0.0.1",
                port,
                key_exchange=key_exchange,
                identity_provider=identity_provider,
                own_identity=_identity(),
            )
            await client.send_hello(device_id=RESPONDER_ID)
            with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
                await client.read_raw()
            await client.close()
            await _wait_until(lambda: errors)

        assert isinstance(errors[0], HandshakeValidationError)


class TestRejectionsLeaveNoTrace:
    """A rejected message 3 must send a reject and write nothing (§6.2)."""

    async def test_a_bad_signature_in_message_3_is_rejected(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
    ) -> None:
        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
        )
        async with responder_server(responder) as (port, errors, results):
            client = await RawInitiator.connect(
                "127.0.0.1",
                port,
                key_exchange=key_exchange,
                identity_provider=identity_provider,
                own_identity=_identity(),
            )
            await client.send_hello()
            await client.read_reply()
            await client.send_confirm(tamper_sig_i=True)
            final = await client.read_final()
            await client.close()
            await _wait_until(lambda: errors)

        assert final.status == STATUS_REJECT
        assert isinstance(errors[0], InvalidHandshakeSignatureError)
        assert not results
        assert await responder_trust.get_trusted_key(INITIATOR_ID) is None

    async def test_a_tampered_mac_i_is_rejected(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
    ) -> None:
        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
        )
        async with responder_server(responder) as (port, errors, results):
            client = await RawInitiator.connect(
                "127.0.0.1",
                port,
                key_exchange=key_exchange,
                identity_provider=identity_provider,
                own_identity=_identity(),
            )
            await client.send_hello()
            await client.read_reply()
            await client.send_confirm(tamper_mac_i=True)
            final = await client.read_final()
            await client.close()
            await _wait_until(lambda: errors)

        assert final.status == STATUS_REJECT
        assert isinstance(errors[0], KeyConfirmationError)
        assert not results
        assert await responder_trust.get_trusted_key(INITIATOR_ID) is None

    async def test_a_malformed_message_3_is_rejected(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
    ) -> None:
        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
        )
        async with responder_server(responder) as (port, errors, results):
            client = await RawInitiator.connect(
                "127.0.0.1",
                port,
                key_exchange=key_exchange,
                identity_provider=identity_provider,
                own_identity=_identity(),
            )
            await client.send_hello()
            await client.read_reply()
            await client.send_confirm(raw=b"\x03\x03\x00")
            final = await client.read_final()
            await client.close()
            await _wait_until(lambda: errors)

        assert final.status == STATUS_REJECT
        assert not results
        assert await responder_trust.get_trusted_key(INITIATOR_ID) is None

    async def test_a_different_pinned_key_is_refused(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
    ) -> None:
        await responder_trust.trust(INITIATOR_ID, b"\x11" * 32)
        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
        )
        async with responder_server(responder) as (port, errors, results):
            client = await RawInitiator.connect(
                "127.0.0.1",
                port,
                key_exchange=key_exchange,
                identity_provider=identity_provider,
                own_identity=_identity(),
            )
            await client.send_hello()
            await client.read_reply()
            await client.send_confirm()
            final = await client.read_final()
            await client.close()
            await _wait_until(lambda: errors)

        assert final.status == STATUS_REJECT
        assert isinstance(errors[0], PeerIdentityMismatchError)
        assert not results
        # The existing pin must survive the refusal.
        assert await responder_trust.get_trusted_key(INITIATOR_ID) == b"\x11" * 32

    async def test_a_colliding_session_id_is_rejected(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
    ) -> None:
        # The store refuses a duplicate session_id; the handshake must turn that
        # into a rejection rather than a half-stored session.
        def on_confirmed(_result: object) -> None:
            raise SessionIdCollisionError("session_id already recorded")

        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
        )
        async with responder_server(responder, on_confirmed=on_confirmed) as (
            port,
            errors,
            results,
        ):
            client = await RawInitiator.connect(
                "127.0.0.1",
                port,
                key_exchange=key_exchange,
                identity_provider=identity_provider,
                own_identity=_identity(),
            )
            await client.send_hello()
            await client.read_reply()
            await client.send_confirm()
            final = await client.read_final()
            await client.close()
            await _wait_until(lambda: errors)

        assert final.status == STATUS_REJECT
        assert isinstance(errors[0], SessionIdCollisionError)
        assert not results

    async def test_a_valid_handshake_gets_an_accept(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
    ) -> None:
        # The control for the reject tests: the same client, uncorrupted.
        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
        )
        async with responder_server(responder) as (port, errors, results):
            client = await RawInitiator.connect(
                "127.0.0.1",
                port,
                key_exchange=key_exchange,
                identity_provider=identity_provider,
                own_identity=_identity(),
            )
            await client.send_hello()
            await client.read_reply()
            await client.send_confirm()
            final = await client.read_final()
            await client.close()
            await _wait_until(lambda: results or errors)

        assert not errors
        assert final.status == STATUS_ACCEPT
        assert final.mac_f == client.expected_accept_mac()
        assert results


class TestAdmissionLimits:
    async def test_the_half_open_cap_is_enforced(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
    ) -> None:
        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
            max_half_open=1,
        )
        async with responder_server(responder) as (port, errors, _results):
            first = await RawInitiator.connect(
                "127.0.0.1",
                port,
                key_exchange=key_exchange,
                identity_provider=identity_provider,
                own_identity=_identity(),
            )
            # Leave the first exchange half-open: message 2 read, no message 3.
            await first.send_hello()
            await first.read_reply()
            await _wait_until(lambda: responder.half_open == 1)

            second = await RawInitiator.connect(
                "127.0.0.1",
                port,
                key_exchange=key_exchange,
                identity_provider=identity_provider,
                own_identity=_identity(),
            )
            await second.send_hello()
            with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
                await second.read_raw()
            await second.close()
            await _wait_until(lambda: errors)

            # Asserted inside the context: leaving it waits for the handlers,
            # and the first exchange is still deliberately half-open.
            assert isinstance(errors[0], HandshakeBusyError)
            assert responder.half_open == 1
            await first.close()

    async def test_the_global_limiter_refuses_a_second_handshake(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
    ) -> None:
        # One token, effectively no refill: the second connection is refused
        # before any message is read.
        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
            global_limiter=GlobalHandshakeLimiter(rate_per_s=1e-9, burst=1),
        )
        async with responder_server(responder) as (port, errors, results):
            first = await RawInitiator.connect(
                "127.0.0.1",
                port,
                key_exchange=key_exchange,
                identity_provider=identity_provider,
                own_identity=_identity(),
            )
            await first.send_hello()
            await first.read_reply()
            await first.send_confirm()
            await first.read_final()
            await first.close()
            await _wait_until(lambda: results)

            second = await RawInitiator.connect(
                "127.0.0.1",
                port,
                key_exchange=key_exchange,
                identity_provider=identity_provider,
                own_identity=_identity(),
            )
            await second.send_hello()
            with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
                await second.read_raw()
            await second.close()
            await _wait_until(lambda: errors)

        assert isinstance(errors[0], HandshakeRateLimitedError)

    async def test_a_silent_connection_hits_the_deadline(
        self,
        identity_provider: Ed25519IdentityProvider,
        key_exchange: PycaKeyExchangeProvider,
        responder_identity: IdentityKeyPair,
        responder_trust: FakeTrustedPeerRepository,
    ) -> None:
        responder = _responder(
            own_identity=responder_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=responder_trust,
            deadline=0.2,
        )
        async with responder_server(responder) as (port, errors, _results):
            client = await RawInitiator.connect(
                "127.0.0.1",
                port,
                key_exchange=key_exchange,
                identity_provider=identity_provider,
                own_identity=_identity(),
            )
            with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
                await client.read_raw()
            await client.close()
            await _wait_until(lambda: errors)

        assert isinstance(errors[0], HandshakeDeadlineError)
