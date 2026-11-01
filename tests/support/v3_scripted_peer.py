"""A scriptable v3 responder, used to drive the initiator through every path.

The production responder only ever behaves well, so it cannot exercise the
initiator's failure handling: a bad ``sig_r``, a tampered ``mac_r``, a
rejection in message 4, a truncated reply or a peer that simply goes quiet.
This peer speaks the protocol from the message layer and the key schedule, and
each misbehaviour is a flag.

It is deliberately *not* a second implementation of the production responder —
it holds no sessions, no trust store and no rate limiting. It exists to be
hostile in exactly one way per test.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from dataclasses import dataclass, field

from securesync.domain.crypto import KeyExchangeProvider
from securesync.domain.identity import IdentityKeyPair, IdentityProvider
from securesync.infrastructure.networking.handshake_keys import (
    HandshakeSecrets,
    confirmation_mac,
    derive_handshake_secrets,
)
from securesync.infrastructure.networking.handshake_messages import (
    HANDSHAKE_VERSION,
    STATUS_ACCEPT,
    STATUS_REJECT,
    ConfirmMessage,
    HelloMessage,
    ReplyMessage,
    decode_confirm,
    decode_hello,
    encode_final,
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
from securesync.infrastructure.networking.message_io import (
    _LENGTH_PREFIX_FORMAT,
    MAX_HANDSHAKE_MESSAGE_SIZE,
    read_length_prefixed,
)

NONCE_SIZE = 32


@dataclass
class ScriptedResponder:
    """Serves one v3 handshake and records what the initiator sent."""

    key_exchange: KeyExchangeProvider
    identity_provider: IdentityProvider
    own_identity: IdentityKeyPair
    device_id: str = "device-beta"
    transfer_port: int = 5001
    manifest_port: int = 5002
    #: Identity key to advertise, when it should differ from the signing key.
    claimed_identity_public_key: bytes | None = None
    #: Private key used to sign ``sig_r``, when it should differ from ours.
    signing_private_key: bytes | None = None
    reject: bool = False
    tamper_sig_r: bool = False
    tamper_mac_r: bool = False
    tamper_mac_f: bool = False
    #: Send this instead of message 2.
    m2_override: bytes | None = None
    #: Read message 1, then never answer.
    silent: bool = False
    #: Fixed responder ephemeral/nonce, for deterministic vectors.
    e_r_private: bytes | None = None
    e_r_public: bytes | None = None
    n_r: bytes | None = None

    port: int = field(default=0, init=False)
    hello: HelloMessage | None = field(default=None, init=False)
    confirm: ConfirmMessage | None = field(default=None, init=False)
    secrets: HandshakeSecrets | None = field(default=None, init=False)
    sig_i_ok: bool | None = field(default=None, init=False)
    mac_i_ok: bool | None = field(default=None, init=False)
    error: BaseException | None = field(default=None, init=False)

    _server: asyncio.AbstractServer | None = field(default=None, init=False, repr=False)
    _task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)
    _done: asyncio.Event = field(default_factory=asyncio.Event, init=False, repr=False)

    async def start(self) -> int:
        """Listen on an ephemeral loopback port and return it."""
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        port = self._server.sockets[0].getsockname()[1]
        assert isinstance(port, int)
        self.port = port
        return port

    async def stop(self) -> None:
        """Stop listening and stop the handler.

        ``Server.wait_closed()`` waits for client handlers to finish on Python
        3.12+, so the handler is cancelled *before* it is awaited; otherwise a
        deliberately silent peer would hold the test for its full sleep.
        """
        if self._server is not None:
            self._server.close()
        if self._task is not None and not self._task.done():
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(asyncio.shield(self._task), 1.0)
            if not self._task.done():
                self._task.cancel()
            with contextlib.suppress(BaseException):
                await self._task
        if self._server is not None:
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    async def wait(self, wait_seconds: float = 5.0) -> None:
        """Wait until the scripted exchange has finished.

        A client that aborts the handshake hangs up, so an incomplete read or a
        reset connection is the expected outcome for a failure test and is not
        re-raised. Any other scripted-peer error is.
        """
        await asyncio.wait_for(self._done.wait(), wait_seconds)
        if self.error is not None and not isinstance(
            self.error, (asyncio.IncompleteReadError, ConnectionError)
        ):
            raise self.error

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._task = asyncio.current_task()
        try:
            await self._exchange(reader, writer)
        except BaseException as exc:
            self.error = exc
        finally:
            self._done.set()
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    @staticmethod
    async def _write(writer: asyncio.StreamWriter, payload: bytes) -> None:
        writer.write(struct.pack(_LENGTH_PREFIX_FORMAT, len(payload)) + payload)
        await writer.drain()

    async def _exchange(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        m1 = await read_length_prefixed(reader, max_size=MAX_HANDSHAKE_MESSAGE_SIZE)
        self.hello = decode_hello(m1)
        if self.silent:
            await asyncio.sleep(30.0)
            return

        private, public = self.key_exchange.generate_key_pair()
        if self.e_r_private is not None:
            private = self.e_r_private
        if self.e_r_public is not None:
            public = self.e_r_public
        nonce = self.n_r if self.n_r is not None else b"\x22" * NONCE_SIZE

        claimed = self.claimed_identity_public_key or self.own_identity.public_key
        signing_key = self.signing_private_key or self.own_identity.private_key

        body = encode_reply_body(
            e_r=public,
            n_r=nonce,
            device_id=self.device_id,
            identity_public_key=claimed,
            transfer_port=self.transfer_port,
            manifest_port=self.manifest_port,
        )
        t2 = transcript_t2(m1, body)
        sig_r = self.identity_provider.sign(signing_key, signed_responder(t2))
        if self.tamper_sig_r:
            sig_r = bytes([sig_r[0] ^ 0xFF]) + sig_r[1:]

        shared_secret = self.key_exchange.derive_shared_secret(private, self.hello.e_i)
        self.secrets = derive_handshake_secrets(
            shared_secret=shared_secret,
            hello=self.hello,
            reply=ReplyMessage(
                version=HANDSHAKE_VERSION,
                e_r=public,
                n_r=nonce,
                device_id=self.device_id,
                identity_public_key=claimed,
                transfer_port=self.transfer_port,
                manifest_port=self.manifest_port,
                sig_r=sig_r,
                mac_r=b"\x00" * 32,
                body=body,
                raw=body,
            ),
            transcript_t2=t2,
        )
        t2s = transcript_t2s(t2, sig_r)
        mac_r = confirmation_mac(self.secrets.responder_confirmation_key, t2s)
        if self.tamper_mac_r:
            mac_r = bytes([mac_r[0] ^ 0xFF]) + mac_r[1:]

        if self.m2_override is not None:
            await self._write(writer, self.m2_override)
        else:
            await self._write(
                writer,
                encode_reply(
                    e_r=public,
                    n_r=nonce,
                    device_id=self.device_id,
                    identity_public_key=claimed,
                    transfer_port=self.transfer_port,
                    manifest_port=self.manifest_port,
                    sig_r=sig_r,
                    mac_r=mac_r,
                ),
            )

        m3 = await read_length_prefixed(reader, max_size=MAX_HANDSHAKE_MESSAGE_SIZE)
        self.confirm = decode_confirm(m3)
        self.sig_i_ok = self.identity_provider.verify(
            self.hello.identity_public_key,
            signed_initiator(t2s),
            self.confirm.sig_i,
        )
        t3 = transcript_t3(t2s, mac_r)
        t3s = transcript_t3s(t3, self.confirm.sig_i)
        expected_mac_i = confirmation_mac(self.secrets.initiator_confirmation_key, t3s)
        self.mac_i_ok = expected_mac_i == self.confirm.mac_i

        if self.reject:
            mac_f = confirmation_mac(
                self.secrets.responder_confirmation_key,
                transcript_m4_reject(t2s, m3),
            )
            await self._write(writer, encode_final(status=STATUS_REJECT, mac_f=mac_f))
            return

        t_final = transcript_final(t3s, self.confirm.mac_i)
        mac_f = confirmation_mac(
            self.secrets.responder_confirmation_key, transcript_m4_accept(t_final)
        )
        if self.tamper_mac_f:
            mac_f = bytes([mac_f[0] ^ 0xFF]) + mac_f[1:]
        await self._write(writer, encode_final(status=STATUS_ACCEPT, mac_f=mac_f))
