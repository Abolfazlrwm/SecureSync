"""v3 SIGMA-style handshake — both halves.

The initiator sends message 1 (``HELLO``, unsigned), reads message 2
(``REPLY``, signed and key-confirmed), sends message 3 (``CONFIRM``, its own
signature over the full transcript plus ``mac_i``), and reads message 4
(``FINAL``, accept/reject plus ``mac_f``). The state machine is the one in
``docs/design/1e-handshake.md`` §6.1:

| State | Event | Next |
|---|---|---|
| ``IDLE`` | ``initiate()`` | build ``m1``, send, ``SENT_HELLO`` |
| ``SENT_HELLO`` | ``m2`` received and fully verified | send ``m3``, ``SENT_CONFIRM`` |
| ``SENT_CONFIRM`` | ``m4`` accept with a valid ``mac_f`` | pin, ``CONFIRMED`` |
| any | any failure | ``FAILED`` |

Three details are deliberate and each has a test:

* **Message 4 decides usability.** Transfers run over concurrent connections,
  so the initiator's first data frame can reach the responder before the
  responder has verified message 3 and stored the session. Treating the
  session as live after ``mac_r`` would produce a window of
  ``UnknownSessionError``; waiting for ``m4`` closes it. The initiator also
  learns about a rejection, which message 2 alone cannot tell it.
* **No pin before the end.** ``trust()`` is called only after ``mac_f``
  verifies. A failed or aborted handshake leaves the trust store untouched —
  pinning at signature-verification time would let an attacker with a valid
  but *unconfirmed* signature permanently occupy a device ID.
* **One absolute deadline.** ``HANDSHAKE_DEADLINE_S`` bounds the whole
  handshake, not each read, so a peer cannot hold a half-open handshake alive
  by trickling bytes.

The responder (§6.2) mirrors it: ``WAIT_HELLO`` → verify and answer with
message 2 → ``SENT_REPLY`` → verify message 3 → pin, record the session, send
message 4 accept → ``CONFIRMED``. Two things are specific to this side:

* **Message 1 is unsigned**, so the responder does only cheap work before
  message 2: a version check, field validation, a self-connection check and
  the two rate limits. Every expensive step (X25519, Ed25519 sign) happens
  once per admitted hello, and ``MAX_HALF_OPEN`` bounds how many such
  exchanges can be in flight at once.
* **The session is recorded before message 4 is sent.** The caller passes
  ``on_confirmed``, which runs once message 3 verifies and before the accept
  leaves the socket, so the initiator's first data frame can never arrive
  ahead of the session it belongs to.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import struct
from collections.abc import Callable
from enum import IntEnum, unique
from typing import Final

import structlog

from securesync.core.protocol import ProtocolError
from securesync.domain.crypto import KeyExchangeProvider
from securesync.domain.identity import IdentityKeyPair, IdentityProvider, TrustedPeerRepository
from securesync.domain.identity_exceptions import (
    InvalidHandshakeSignatureError,
    PeerIdentityMismatchError,
)
from securesync.infrastructure.networking.handshake_keys import (
    HandshakeSecrets,
    confirmation_mac,
    derive_handshake_secrets,
    keys_for_role,
    verify_confirmation_mac,
)
from securesync.infrastructure.networking.handshake_messages import (
    HANDSHAKE_VERSION,
    MAC_SIZE,
    NONCE_SIZE,
    STATUS_ACCEPT,
    STATUS_REJECT,
    ConfirmMessage,
    HelloMessage,
    ReplyMessage,
    check_not_self,
    decode_confirm,
    decode_final,
    decode_hello,
    decode_reply,
    encode_confirm,
    encode_final,
    encode_hello,
    encode_reply,
    encode_reply_body,
    signed_initiator,
    signed_responder,
    transcript_final,
    transcript_m4_accept,
    transcript_m4_reject,
    transcript_t2,
    transcript_t2s,
    transcript_t3,
    transcript_t3s,
)
from securesync.infrastructure.networking.handshake_rate_limit import GlobalHandshakeLimiter
from securesync.infrastructure.networking.message_io import (
    _LENGTH_PREFIX_FORMAT,
    MAX_HANDSHAKE_MESSAGE_SIZE,
    MessageReadTimeoutError,
    read_length_prefixed,
)
from securesync.infrastructure.networking.replay_protection import (
    ROLE_INITIATOR,
    ROLE_RESPONDER,
)
from securesync.infrastructure.networking.x25519_handshake import HandshakeResult

logger = structlog.get_logger(__name__)

#: One deadline for the whole handshake (design §6.3). Measured from the
#: moment ``initiate()`` starts, and clamped into every individual wait.
HANDSHAKE_DEADLINE_S: Final = 10.0


@unique
class HandshakeState(IntEnum):
    """States of the initiator state machine (design §6.1)."""

    IDLE = 0
    SENT_HELLO = 1
    SENT_CONFIRM = 2
    CONFIRMED = 3
    FAILED = 4


class HandshakeError(ProtocolError):
    """Base class for v3 handshake failures."""


class HandshakeDeadlineError(HandshakeError):
    """The absolute handshake deadline expired."""


class HandshakeRejectedError(HandshakeError):
    """The responder rejected the handshake in message 4."""


class HandshakeStateError(HandshakeError):
    """The state machine was driven in an order it does not allow."""


class _Exchange:
    """One handshake attempt, with its own deadline-bounded I/O.

    A fresh instance is created per attempt, so nothing here is shared between
    concurrent handshakes and :class:`HandshakeV3` itself stays stateless.
    """

    def __init__(
        self,
        *,
        owner: HandshakeV3,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._owner = owner
        self._reader = reader
        self._writer = writer
        self._deadline_at = asyncio.get_running_loop().time() + owner.deadline

    # --- deadline-bounded I/O ----------------------------------------------

    def _remaining(self) -> float:
        remaining = self._deadline_at - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise HandshakeDeadlineError("handshake deadline exceeded")
        return remaining

    async def _read(self) -> bytes:
        remaining = self._remaining()
        try:
            return await asyncio.wait_for(
                read_length_prefixed(
                    self._reader,
                    max_size=MAX_HANDSHAKE_MESSAGE_SIZE,
                    read_timeout=remaining,
                ),
                remaining,
            )
        except (TimeoutError, MessageReadTimeoutError) as exc:
            raise HandshakeDeadlineError("deadline exceeded while waiting for a message") from exc

    async def _write(self, payload: bytes) -> None:
        remaining = self._remaining()
        frame = struct.pack(_LENGTH_PREFIX_FORMAT, len(payload)) + payload
        try:
            self._writer.write(frame)
            await asyncio.wait_for(self._writer.drain(), remaining)
        except TimeoutError as exc:
            raise HandshakeDeadlineError("deadline exceeded while sending a message") from exc


class _InitiatorExchange(_Exchange):
    """The initiator side of one handshake attempt."""

    def __init__(
        self,
        *,
        owner: HandshakeV3,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        super().__init__(owner=owner, reader=reader, writer=writer)
        self.state = HandshakeState.IDLE

        self._deadline_at = asyncio.get_running_loop().time() + owner.deadline

    # --- deadline-bounded I/O ----------------------------------------------

    def _remaining(self) -> float:
        remaining = self._deadline_at - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise HandshakeDeadlineError("handshake deadline exceeded")
        return remaining

    async def _read(self) -> bytes:
        remaining = self._remaining()
        try:
            return await asyncio.wait_for(
                read_length_prefixed(
                    self._reader,
                    max_size=MAX_HANDSHAKE_MESSAGE_SIZE,
                    read_timeout=remaining,
                ),
                remaining,
            )
        except (TimeoutError, MessageReadTimeoutError) as exc:
            raise HandshakeDeadlineError("deadline exceeded while waiting for a message") from exc

    async def _write(self, payload: bytes) -> None:
        remaining = self._remaining()
        frame = struct.pack(_LENGTH_PREFIX_FORMAT, len(payload)) + payload
        try:
            self._writer.write(frame)
            await asyncio.wait_for(self._writer.drain(), remaining)
        except TimeoutError as exc:
            raise HandshakeDeadlineError("deadline exceeded while sending a message") from exc

    # --- the four flights ---------------------------------------------------

    async def run(self) -> HandshakeResult:
        """Drive the state machine to ``CONFIRMED`` or ``FAILED``."""
        try:
            result = await self._exchange()
        except BaseException:
            self.state = HandshakeState.FAILED
            raise
        self.state = HandshakeState.CONFIRMED
        return result

    async def _exchange(self) -> HandshakeResult:
        owner = self._owner

        # IDLE -> SENT_HELLO
        ephemeral_private, ephemeral_public = owner.generate_key_pair()
        nonce = owner.generate_nonce()
        hello_bytes = encode_hello(
            e_i=ephemeral_public,
            n_i=nonce,
            device_id=owner.own_device_id,
            identity_public_key=owner.own_identity.public_key,
            transfer_port=owner.own_transfer_port,
            manifest_port=owner.own_manifest_port,
        )
        await self._write(hello_bytes)
        self.state = HandshakeState.SENT_HELLO

        # SENT_HELLO -> SENT_CONFIRM
        reply_bytes = await self._read()
        reply = decode_reply(reply_bytes)
        check_not_self(
            reply.device_id,
            reply.identity_public_key,
            owner.own_device_id,
            owner.own_identity.public_key,
        )

        # Decode our own message 1 so the key schedule consumes exactly the
        # bytes that went on the wire, not a second encoder pass.
        hello = decode_hello(hello_bytes)
        t2 = transcript_t2(hello_bytes, reply.body)
        if not owner.identity_provider.verify(
            reply.identity_public_key, signed_responder(t2), reply.sig_r
        ):
            raise InvalidHandshakeSignatureError(
                f"reply signature from {reply.device_id!r} does not verify"
            )

        # Trust-on-first-use is *checked* here but not written (design §4.9).
        trusted_key = await owner.trusted_peers.get_trusted_key(reply.device_id)
        if trusted_key is not None and trusted_key != reply.identity_public_key:
            raise PeerIdentityMismatchError(
                f"{reply.device_id!r} presented a different identity key than previously trusted"
            )

        shared_secret = owner.key_exchange.derive_shared_secret(ephemeral_private, reply.e_r)
        secrets = derive_handshake_secrets(
            shared_secret=shared_secret,
            hello=hello,
            reply=reply,
            transcript_t2=t2,
        )

        t2s = transcript_t2s(t2, reply.sig_r)
        verify_confirmation_mac(secrets.responder_confirmation_key, t2s, reply.mac_r)

        t3 = transcript_t3(t2s, reply.mac_r)
        sig_i = owner.identity_provider.sign(owner.own_identity.private_key, signed_initiator(t2s))
        t3s = transcript_t3s(t3, sig_i)
        mac_i = confirmation_mac(secrets.initiator_confirmation_key, t3s)
        await self._write(encode_confirm(sig_i=sig_i, mac_i=mac_i))
        self.state = HandshakeState.SENT_CONFIRM

        # SENT_CONFIRM -> CONFIRMED
        final = decode_final(await self._read())
        if final.status != STATUS_ACCEPT:
            raise HandshakeRejectedError(f"{reply.device_id!r} rejected the handshake")

        t_final = transcript_final(t3s, mac_i)
        verify_confirmation_mac(
            secrets.responder_confirmation_key,
            transcript_m4_accept(t_final),
            final.mac_f,
        )

        # Only now, with every flight verified, is the pin written.
        await owner.trusted_peers.trust(reply.device_id, reply.identity_public_key)

        keys = keys_for_role(secrets, ROLE_INITIATOR)
        logger.info("handshake_completed_as_initiator", peer_device_id=reply.device_id)
        return HandshakeResult(
            peer_device_id=reply.device_id,
            session_id=keys.session_id,
            role=ROLE_INITIATOR,
            send_key=keys.send_key,
            receive_key=keys.receive_key,
            peer_transfer_port=reply.transfer_port,
            peer_manifest_port=reply.manifest_port,
        )


#: How many responder exchanges may sit between message 2 and message 4.
#: Design §6.3: ``SENT_REPLY`` is the half-open state and counts against this.
MAX_HALF_OPEN: Final = 64


@unique
class ResponderState(IntEnum):
    """States of the responder state machine (design §6.2)."""

    WAIT_HELLO = 0
    SENT_REPLY = 1
    CONFIRMED = 2
    FAILED = 3


class HandshakeBusyError(HandshakeError):
    """Too many handshakes are already half-open on this responder."""


class HandshakeRateLimitedError(HandshakeError):
    """The process-wide handshake admission rate has been exceeded."""


class _ResponderExchange(_Exchange):
    """The responder side of one handshake attempt."""

    def __init__(
        self,
        *,
        owner: HandshakeV3,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        on_confirmed: Callable[[HandshakeResult], None] | None,
    ) -> None:
        super().__init__(owner=owner, reader=reader, writer=writer)
        self._on_confirmed = on_confirmed
        self.state = ResponderState.WAIT_HELLO

    async def run(self) -> HandshakeResult:
        """Drive the state machine to ``CONFIRMED`` or ``FAILED``."""
        try:
            result = await self._exchange()
        except BaseException:
            self.state = ResponderState.FAILED
            raise
        self.state = ResponderState.CONFIRMED
        return result

    async def _exchange(self) -> HandshakeResult:
        owner = self._owner

        # WAIT_HELLO: only cheap work before message 2.
        m1 = await self._read()
        hello = decode_hello(m1)
        check_not_self(
            hello.device_id,
            hello.identity_public_key,
            owner.own_device_id,
            owner.own_identity.public_key,
        )

        owner.begin_half_open()
        try:
            ephemeral_private, ephemeral_public = owner.generate_key_pair()
            nonce = owner.generate_nonce()
            body = encode_reply_body(
                e_r=ephemeral_public,
                n_r=nonce,
                device_id=owner.own_device_id,
                identity_public_key=owner.own_identity.public_key,
                transfer_port=owner.own_transfer_port,
                manifest_port=owner.own_manifest_port,
            )
            t2 = transcript_t2(m1, body)
            sig_r = owner.identity_provider.sign(
                owner.own_identity.private_key, signed_responder(t2)
            )
            shared_secret = owner.key_exchange.derive_shared_secret(ephemeral_private, hello.e_i)
            secrets = derive_handshake_secrets(
                shared_secret=shared_secret,
                hello=hello,
                reply=ReplyMessage(
                    version=HANDSHAKE_VERSION,
                    e_r=ephemeral_public,
                    n_r=nonce,
                    device_id=owner.own_device_id,
                    identity_public_key=owner.own_identity.public_key,
                    transfer_port=owner.own_transfer_port,
                    manifest_port=owner.own_manifest_port,
                    sig_r=sig_r,
                    mac_r=b"\x00" * MAC_SIZE,
                    body=body,
                    raw=body,
                ),
                transcript_t2=t2,
            )
            t2s = transcript_t2s(t2, sig_r)
            mac_r = confirmation_mac(secrets.responder_confirmation_key, t2s)
            await self._write(
                encode_reply(
                    e_r=ephemeral_public,
                    n_r=nonce,
                    device_id=owner.own_device_id,
                    identity_public_key=owner.own_identity.public_key,
                    transfer_port=owner.own_transfer_port,
                    manifest_port=owner.own_manifest_port,
                    sig_r=sig_r,
                    mac_r=mac_r,
                )
            )
            self.state = ResponderState.SENT_REPLY

            # SENT_REPLY: any failure from here on gets a best-effort reject.
            m3 = await self._read()
            try:
                confirm, t3s, result = await self._verify_message_3(m3, hello, secrets, t2s, mac_r)
            except BaseException:
                await self._reject(t2s, m3, secrets)
                raise

            t_final = transcript_final(t3s, confirm.mac_i)
            mac_f = confirmation_mac(
                secrets.responder_confirmation_key, transcript_m4_accept(t_final)
            )
            await self._write(encode_final(status=STATUS_ACCEPT, mac_f=mac_f))
        finally:
            owner.end_half_open()

        logger.info("handshake_completed_as_responder", peer_device_id=hello.device_id)
        return result

    async def _verify_message_3(
        self,
        m3: bytes,
        hello: HelloMessage,
        secrets: HandshakeSecrets,
        t2s: bytes,
        mac_r: bytes,
    ) -> tuple[ConfirmMessage, bytes, HandshakeResult]:
        """Verify message 3 and, only then, pin and record the session."""
        owner = self._owner
        confirm = decode_confirm(m3)
        t3 = transcript_t3(t2s, mac_r)
        t3s = transcript_t3s(t3, confirm.sig_i)

        if not owner.identity_provider.verify(
            hello.identity_public_key, signed_initiator(t2s), confirm.sig_i
        ):
            raise InvalidHandshakeSignatureError(
                f"confirm signature from {hello.device_id!r} does not verify"
            )
        trusted_key = await owner.trusted_peers.get_trusted_key(hello.device_id)
        if trusted_key is not None and trusted_key != hello.identity_public_key:
            raise PeerIdentityMismatchError(
                f"{hello.device_id!r} presented a different identity key than previously trusted"
            )
        verify_confirmation_mac(secrets.initiator_confirmation_key, t3s, confirm.mac_i)

        # Signature and MAC both verified: only now is the pin written.
        await owner.trusted_peers.trust(hello.device_id, hello.identity_public_key)

        keys = keys_for_role(secrets, ROLE_RESPONDER)
        result = HandshakeResult(
            peer_device_id=hello.device_id,
            session_id=keys.session_id,
            role=ROLE_RESPONDER,
            send_key=keys.send_key,
            receive_key=keys.receive_key,
            peer_transfer_port=hello.transfer_port,
            peer_manifest_port=hello.manifest_port,
        )
        # Record the session *before* message 4 leaves, so the initiator's
        # first data frame can never arrive ahead of it.
        if self._on_confirmed is not None:
            self._on_confirmed(result)
        return confirm, t3s, result

    async def _reject(self, t2s: bytes, m3_raw: bytes, secrets: HandshakeSecrets) -> None:
        """Send message 4 reject, best effort; never pin, never store."""
        with contextlib.suppress(Exception):
            mac_f = confirmation_mac(
                secrets.responder_confirmation_key, transcript_m4_reject(t2s, m3_raw)
            )
            await self._write(encode_final(status=STATUS_REJECT, mac_f=mac_f))


class HandshakeV3:
    """Performs the v3 handshake. Holds configuration, not handshake state."""

    def __init__(
        self,
        own_device_id: str,
        own_transfer_port: int,
        own_manifest_port: int,
        key_exchange: KeyExchangeProvider,
        identity_provider: IdentityProvider,
        own_identity: IdentityKeyPair,
        trusted_peers: TrustedPeerRepository,
        *,
        deadline: float = HANDSHAKE_DEADLINE_S,
        max_half_open: int = MAX_HALF_OPEN,
        global_limiter: GlobalHandshakeLimiter | None = None,
        key_pair_factory: Callable[[], tuple[bytes, bytes]] | None = None,
        nonce_factory: Callable[[], bytes] | None = None,
    ) -> None:
        """Initialize the handshake.

        Args:
            own_device_id: This device's ID, sent in message 1.
            own_transfer_port: This device's chunk-transfer port.
            own_manifest_port: This device's manifest-exchange port.
            key_exchange: Generates ephemeral keypairs and derives the ECDH
                shared secret.
            identity_provider: Signs outgoing and verifies incoming messages.
            own_identity: This device's long-term Ed25519 identity keypair.
            trusted_peers: Pins and checks the peer's long-term public key.
            deadline: Absolute deadline for the whole handshake, in seconds.
            max_half_open: How many responder exchanges may sit between
                message 2 and message 4 at once.
            global_limiter: Process-wide admission bucket. A default is
                created when omitted; share one instance across the
                responder's connections to make the cap global.
            key_pair_factory: **Test-only.** Overrides ephemeral keypair
                generation so a known-answer test can pin ``e_i``.
            nonce_factory: **Test-only.** Overrides nonce generation so a
                known-answer test can pin ``n_i``.
        """
        self.own_device_id = own_device_id
        self.own_transfer_port = own_transfer_port
        self.own_manifest_port = own_manifest_port
        self.key_exchange = key_exchange
        self.identity_provider = identity_provider
        self.own_identity = own_identity
        self.trusted_peers = trusted_peers
        self.deadline = deadline
        self.max_half_open = max_half_open
        self.global_limiter = global_limiter or GlobalHandshakeLimiter()
        self._half_open = 0
        self._key_pair_factory = key_pair_factory or key_exchange.generate_key_pair
        self._nonce_factory = nonce_factory or (lambda: os.urandom(NONCE_SIZE))

    def generate_key_pair(self) -> tuple[bytes, bytes]:
        """Return the ephemeral keypair for this handshake."""
        return self._key_pair_factory()

    def generate_nonce(self) -> bytes:
        """Return the fresh nonce for this handshake."""
        nonce = self._nonce_factory()
        if len(nonce) != NONCE_SIZE:
            raise HandshakeStateError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
        return nonce

    async def initiate(self, host: str, port: int) -> HandshakeResult:
        """Connect to a peer and complete the handshake as the initiator.

        Args:
            host: The peer's handshake host.
            port: The peer's handshake port.

        Returns:
            The negotiated :class:`HandshakeResult`, valid only after message 4
            has been verified.

        Raises:
            OSError: If the connection cannot be established.
            HandshakeDeadlineError: If the absolute deadline expires.
            HandshakeRejectedError: If the responder rejects in message 4.
            InvalidHandshakeSignatureError: If ``sig_r`` does not verify.
            PeerIdentityMismatchError: If the peer's key differs from the pin.
            KeyConfirmationError: If ``mac_r`` or ``mac_f`` does not verify.
            HandshakeDecodeError: If a message is malformed.
            HandshakeValidationError: If a message is out of range or a peer
                claims our own identity.
            UnsupportedVersionError: If the peer speaks another version.
            LowOrderPointError: If a peer sends a degenerate ephemeral key.
        """
        reader, writer = await asyncio.open_connection(host, port)
        try:
            return await self._initiate_on(reader, writer)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    async def _initiate_on(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> HandshakeResult:
        """Run the exchange over an already-open connection."""
        return await _InitiatorExchange(owner=self, reader=reader, writer=writer).run()

    def begin_half_open(self) -> None:
        """Count one more half-open exchange.

        Raises:
            HandshakeBusyError: If ``max_half_open`` exchanges are already in
                flight. The caller answers with a closed connection rather
                than spending curve arithmetic on a peer we cannot serve.
        """
        if self._half_open >= self.max_half_open:
            raise HandshakeBusyError(f"{self._half_open} half-open handshakes already in flight")
        self._half_open += 1

    def end_half_open(self) -> None:
        """Count one fewer half-open exchange."""
        if self._half_open > 0:
            self._half_open -= 1

    @property
    def half_open(self) -> int:
        """How many responder exchanges are between message 2 and message 4."""
        return self._half_open

    async def accept(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        on_confirmed: Callable[[HandshakeResult], None] | None = None,
    ) -> HandshakeResult:
        """Complete the handshake as the responder on an inbound connection.

        Args:
            reader: The inbound connection's stream reader.
            writer: The inbound connection's stream writer.
            on_confirmed: Called with the result once message 3 verifies and
                **before** message 4 is sent. Recording the session here is
                what closes the race between the accept and the initiator's
                first data frame.

        Returns:
            The negotiated :class:`HandshakeResult`.

        Raises:
            HandshakeRateLimitedError: If the process-wide cap is exceeded.
            HandshakeBusyError: If too many exchanges are half-open.
            HandshakeDeadlineError: If the absolute deadline expires.
            InvalidHandshakeSignatureError: If ``sig_i`` does not verify.
            PeerIdentityMismatchError: If the peer's key differs from the pin.
            KeyConfirmationError: If ``mac_i`` does not verify.
            HandshakeDecodeError: If a message is malformed.
            HandshakeValidationError: If a message is out of range or the peer
                claims our own identity.
            UnsupportedVersionError: If the peer speaks another version.
            LowOrderPointError: If the peer sends a degenerate ephemeral key.
        """
        if not self.global_limiter.allow():
            raise HandshakeRateLimitedError("global handshake rate limit exceeded")
        return await _ResponderExchange(
            owner=self,
            reader=reader,
            writer=writer,
            on_confirmed=on_confirmed,
        ).run()
