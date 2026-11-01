"""Tests for the v3 initiator state machine (design §6.1).

Every test drives the real initiator against
:class:`tests.support.v3_scripted_peer.ScriptedResponder`, which can misbehave
in exactly one way per test. The two properties that matter most — message 4
decides usability, and the trust store is never written on a failure path —
each have a dedicated test.
"""

from __future__ import annotations

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
from securesync.infrastructure.networking.handshake_keys import (
    KeyConfirmationError,
    keys_for_role,
)
from securesync.infrastructure.networking.handshake_messages import (
    HandshakeDecodeError,
    HandshakeValidationError,
    encode_reply_body,
)
from securesync.infrastructure.networking.handshake_v3 import (
    HandshakeDeadlineError,
    HandshakeRejectedError,
    HandshakeStateError,
    HandshakeV3,
)
from securesync.infrastructure.networking.replay_protection import (
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    UnsupportedVersionError,
)
from tests.doubles import FakeTrustedPeerRepository
from tests.support.v3_scripted_peer import ScriptedResponder

OWN_DEVICE_ID = "device-alpha"
PEER_DEVICE_ID = "device-beta"


def _identity() -> IdentityKeyPair:
    private = Ed25519PrivateKey.generate()
    return IdentityKeyPair(
        private_key=private.private_bytes_raw(),
        public_key=private.public_key().public_bytes_raw(),
    )


@pytest.fixture
def identity_provider(tmp_path: Path) -> Ed25519IdentityProvider:
    """The real Ed25519 provider; the storage dir is never touched."""
    return Ed25519IdentityProvider(tmp_path / "identity")


@pytest.fixture
def own_identity() -> IdentityKeyPair:
    return _identity()


@pytest.fixture
def key_exchange() -> PycaKeyExchangeProvider:
    return PycaKeyExchangeProvider()


@pytest.fixture
def trusted_peers() -> FakeTrustedPeerRepository:
    return FakeTrustedPeerRepository()


def _initiator(
    *,
    own_identity: IdentityKeyPair,
    identity_provider: Ed25519IdentityProvider,
    key_exchange: PycaKeyExchangeProvider,
    trusted_peers: FakeTrustedPeerRepository,
    deadline: float = 10.0,
) -> HandshakeV3:
    return HandshakeV3(
        OWN_DEVICE_ID,
        5000,
        5001,
        key_exchange,
        identity_provider,
        own_identity,
        trusted_peers,
        deadline=deadline,
    )


@asynccontextmanager
async def responder(
    *,
    identity_provider: Ed25519IdentityProvider,
    key_exchange: PycaKeyExchangeProvider,
    own_identity: IdentityKeyPair | None = None,
    **overrides: object,
) -> AsyncIterator[ScriptedResponder]:
    peer = ScriptedResponder(
        key_exchange=key_exchange,
        identity_provider=identity_provider,
        own_identity=own_identity or _identity(),
        **overrides,  # type: ignore[arg-type]
    )
    await peer.start()
    try:
        yield peer
    finally:
        await peer.stop()


class TestSuccessfulHandshake:
    async def test_returns_a_session_bound_to_the_peer(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            device_id=PEER_DEVICE_ID,
            transfer_port=6000,
            manifest_port=6001,
        ) as peer:
            result = await _initiator(
                own_identity=own_identity,
                identity_provider=identity_provider,
                key_exchange=key_exchange,
                trusted_peers=trusted_peers,
            ).initiate("127.0.0.1", peer.port)
            await peer.wait()

        assert result.peer_device_id == PEER_DEVICE_ID
        assert result.role == ROLE_INITIATOR
        assert len(result.session_id) == 8
        assert result.peer_transfer_port == 6000
        assert result.peer_manifest_port == 6001
        assert len(result.send_key) == 32
        assert result.send_key != result.receive_key

    async def test_the_responder_derives_the_mirror_keys(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
        ) as peer:
            result = await _initiator(
                own_identity=own_identity,
                identity_provider=identity_provider,
                key_exchange=key_exchange,
                trusted_peers=trusted_peers,
            ).initiate("127.0.0.1", peer.port)
            await peer.wait()

        assert peer.secrets is not None
        responder_keys = keys_for_role(peer.secrets, ROLE_RESPONDER)
        assert responder_keys.session_id == result.session_id
        assert responder_keys.receive_key == result.send_key
        assert responder_keys.send_key == result.receive_key

    async def test_message_3_carries_a_valid_signature_and_mac(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        # The scripted peer verifies message 3 exactly as the real responder
        # will: the initiator's signature over t2s and mac_i under k_i.
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
        ) as peer:
            await _initiator(
                own_identity=own_identity,
                identity_provider=identity_provider,
                key_exchange=key_exchange,
                trusted_peers=trusted_peers,
            ).initiate("127.0.0.1", peer.port)
            await peer.wait()

        assert peer.sig_i_ok is True
        assert peer.mac_i_ok is True

    async def test_the_peer_is_pinned_once_the_handshake_verifies(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        peer_identity = _identity()
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            own_identity=peer_identity,
        ) as peer:
            await _initiator(
                own_identity=own_identity,
                identity_provider=identity_provider,
                key_exchange=key_exchange,
                trusted_peers=trusted_peers,
            ).initiate("127.0.0.1", peer.port)
            await peer.wait()

        assert await trusted_peers.get_trusted_key(PEER_DEVICE_ID) == peer_identity.public_key

    async def test_an_already_pinned_peer_is_accepted(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        peer_identity = _identity()
        await trusted_peers.trust(PEER_DEVICE_ID, peer_identity.public_key)
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            own_identity=peer_identity,
        ) as peer:
            result = await _initiator(
                own_identity=own_identity,
                identity_provider=identity_provider,
                key_exchange=key_exchange,
                trusted_peers=trusted_peers,
            ).initiate("127.0.0.1", peer.port)
            await peer.wait()

        assert result.peer_device_id == PEER_DEVICE_ID

    async def test_the_same_instance_can_run_a_second_handshake(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        # The handshake object holds configuration, not state: a failed attempt
        # must not poison the next one.
        initiator = _initiator(
            own_identity=own_identity,
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            trusted_peers=trusted_peers,
        )
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            tamper_mac_f=True,
        ) as broken:
            with pytest.raises(KeyConfirmationError):
                await initiator.initiate("127.0.0.1", broken.port)
            await broken.wait()

        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
        ) as good:
            result = await initiator.initiate("127.0.0.1", good.port)
            await good.wait()

        assert result.peer_device_id == PEER_DEVICE_ID


class TestFailurePathsLeaveNoTrace:
    """Every abort must leave the trust store untouched (design §4.9)."""

    async def test_rejection_in_message_4(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            reject=True,
        ) as peer:
            with pytest.raises(HandshakeRejectedError):
                await _initiator(
                    own_identity=own_identity,
                    identity_provider=identity_provider,
                    key_exchange=key_exchange,
                    trusted_peers=trusted_peers,
                ).initiate("127.0.0.1", peer.port)
            await peer.wait()

        assert await trusted_peers.get_trusted_key(PEER_DEVICE_ID) is None

    async def test_bad_signature_in_message_2(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            tamper_sig_r=True,
        ) as peer:
            with pytest.raises(InvalidHandshakeSignatureError):
                await _initiator(
                    own_identity=own_identity,
                    identity_provider=identity_provider,
                    key_exchange=key_exchange,
                    trusted_peers=trusted_peers,
                ).initiate("127.0.0.1", peer.port)
            await peer.wait()

        assert await trusted_peers.get_trusted_key(PEER_DEVICE_ID) is None

    async def test_tampered_mac_r(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            tamper_mac_r=True,
        ) as peer:
            with pytest.raises(KeyConfirmationError):
                await _initiator(
                    own_identity=own_identity,
                    identity_provider=identity_provider,
                    key_exchange=key_exchange,
                    trusted_peers=trusted_peers,
                ).initiate("127.0.0.1", peer.port)
            await peer.wait()

        assert await trusted_peers.get_trusted_key(PEER_DEVICE_ID) is None

    async def test_tampered_mac_f_does_not_pin(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        # This is the amendment-2 test: everything up to and including sig_r
        # verified, yet the pin must still not be written.
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            tamper_mac_f=True,
        ) as peer:
            with pytest.raises(KeyConfirmationError):
                await _initiator(
                    own_identity=own_identity,
                    identity_provider=identity_provider,
                    key_exchange=key_exchange,
                    trusted_peers=trusted_peers,
                ).initiate("127.0.0.1", peer.port)
            await peer.wait()

        assert await trusted_peers.get_trusted_key(PEER_DEVICE_ID) is None

    async def test_a_different_pinned_key_is_refused(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        await trusted_peers.trust(PEER_DEVICE_ID, b"\x11" * 32)
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
        ) as peer:
            with pytest.raises(PeerIdentityMismatchError):
                await _initiator(
                    own_identity=own_identity,
                    identity_provider=identity_provider,
                    key_exchange=key_exchange,
                    trusted_peers=trusted_peers,
                ).initiate("127.0.0.1", peer.port)
            await peer.stop()

        # The refusal must not overwrite the existing pin either.
        assert await trusted_peers.get_trusted_key(PEER_DEVICE_ID) == b"\x11" * 32

    async def test_a_silent_peer_hits_the_absolute_deadline(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            silent=True,
        ) as peer:
            with pytest.raises(HandshakeDeadlineError):
                await _initiator(
                    own_identity=own_identity,
                    identity_provider=identity_provider,
                    key_exchange=key_exchange,
                    trusted_peers=trusted_peers,
                    deadline=0.25,
                ).initiate("127.0.0.1", peer.port)

        assert await trusted_peers.get_trusted_key(PEER_DEVICE_ID) is None


class TestPeerInputValidation:
    async def test_a_peer_claiming_our_device_id_is_refused(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            device_id=OWN_DEVICE_ID,
        ) as peer:
            with pytest.raises(HandshakeValidationError):
                await _initiator(
                    own_identity=own_identity,
                    identity_provider=identity_provider,
                    key_exchange=key_exchange,
                    trusted_peers=trusted_peers,
                ).initiate("127.0.0.1", peer.port)
            await peer.stop()

    async def test_a_peer_claiming_our_identity_key_is_refused(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            claimed_identity_public_key=own_identity.public_key,
        ) as peer:
            with pytest.raises(HandshakeValidationError):
                await _initiator(
                    own_identity=own_identity,
                    identity_provider=identity_provider,
                    key_exchange=key_exchange,
                    trusted_peers=trusted_peers,
                ).initiate("127.0.0.1", peer.port)
            await peer.stop()

    async def test_a_reply_with_the_wrong_version_is_refused(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        # The encoder refuses to emit a v2 body, so build a valid v3 one and
        # put a v2 version byte in front of it: exactly what a v2 peer's reply
        # looks like to a v3 decoder.
        body = encode_reply_body(
            e_r=b"\x02" * 32,
            n_r=b"\x03" * 32,
            device_id=PEER_DEVICE_ID,
            identity_public_key=b"\x04" * 32,
            transfer_port=5001,
            manifest_port=5002,
        )
        stale = b"\x02" + body[1:] + b"\x00" * 96
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            m2_override=stale,
        ) as peer:
            with pytest.raises(UnsupportedVersionError):
                await _initiator(
                    own_identity=own_identity,
                    identity_provider=identity_provider,
                    key_exchange=key_exchange,
                    trusted_peers=trusted_peers,
                ).initiate("127.0.0.1", peer.port)
            await peer.stop()

    async def test_a_truncated_reply_is_refused(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        async with responder(
            identity_provider=identity_provider,
            key_exchange=key_exchange,
            m2_override=b"\x03\x02\x00",
        ) as peer:
            with pytest.raises(HandshakeDecodeError):
                await _initiator(
                    own_identity=own_identity,
                    identity_provider=identity_provider,
                    key_exchange=key_exchange,
                    trusted_peers=trusted_peers,
                ).initiate("127.0.0.1", peer.port)
            await peer.stop()


class TestConfiguration:
    def test_a_bad_nonce_factory_is_rejected(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        initiator = HandshakeV3(
            OWN_DEVICE_ID,
            5000,
            5001,
            key_exchange,
            identity_provider,
            own_identity,
            trusted_peers,
            nonce_factory=lambda: b"\x00" * 31,
        )
        with pytest.raises(HandshakeStateError):
            initiator.generate_nonce()

    def test_the_injected_factories_are_used(
        self,
        identity_provider: Ed25519IdentityProvider,
        own_identity: IdentityKeyPair,
        key_exchange: PycaKeyExchangeProvider,
        trusted_peers: FakeTrustedPeerRepository,
    ) -> None:
        # The seam that makes a full four-flight known-answer test possible.
        fixed_pair = (b"\x01" * 32, b"\x02" * 32)
        initiator = HandshakeV3(
            OWN_DEVICE_ID,
            5000,
            5001,
            key_exchange,
            identity_provider,
            own_identity,
            trusted_peers,
            key_pair_factory=lambda: fixed_pair,
            nonce_factory=lambda: b"\x07" * 32,
        )
        assert initiator.generate_key_pair() == fixed_pair
        assert initiator.generate_nonce() == b"\x07" * 32
