"""A raw v3 initiator, used to drive the responder through every path.

:class:`tests.support.v3_scripted_peer.ScriptedResponder` is the hostile peer
for the initiator's tests; this is its mirror. It performs the four flights
one step at a time so a test can corrupt a single message — a bad ``sig_i``, a
tampered ``mac_i``, a v2 version byte — and then look at what the responder
did: a reject, no pin, no session.

It is not a second implementation of the production initiator: it does no
trust checking and keeps no state beyond the current exchange.
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
    NONCE_SIZE,
    ConfirmMessage,
    FinalMessage,
    ReplyMessage,
    decode_final,
    decode_hello,
    decode_reply,
    encode_confirm,
    encode_hello,
    signed_initiator,
    transcript_final,
    transcript_m4_accept,
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


@dataclass
class RawInitiator:
    """Sends each handshake message individually so a test can corrupt one."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    key_exchange: KeyExchangeProvider
    identity_provider: IdentityProvider
    own_identity: IdentityKeyPair
    device_id: str = "device-alpha"
    transfer_port: int = 5000
    manifest_port: int = 5001

    hello_bytes: bytes = field(default=b"", init=False)
    reply: ReplyMessage | None = field(default=None, init=False)
    confirm: ConfirmMessage | None = field(default=None, init=False)
    secrets: HandshakeSecrets | None = field(default=None, init=False)
    sig_i: bytes = field(default=b"", init=False)
    mac_i: bytes = field(default=b"", init=False)
    t3s: bytes = field(default=b"", init=False)
    final: FinalMessage | None = field(default=None, init=False)
    _ephemeral_private: bytes = field(default=b"", init=False, repr=False)
    _t2s: bytes = field(default=b"", init=False, repr=False)

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int,
        *,
        key_exchange: KeyExchangeProvider,
        identity_provider: IdentityProvider,
        own_identity: IdentityKeyPair,
        device_id: str = "device-alpha",
        transfer_port: int = 5000,
        manifest_port: int = 5001,
    ) -> RawInitiator:
        """Open a connection and return a peer ready to send message 1."""
        reader, writer = await asyncio.open_connection(host, port)
        return cls(
            reader=reader,
            writer=writer,
            key_exchange=key_exchange,
            identity_provider=identity_provider,
            own_identity=own_identity,
            device_id=device_id,
            transfer_port=transfer_port,
            manifest_port=manifest_port,
        )

    async def send_raw(self, payload: bytes) -> None:
        """Send arbitrary bytes as one length-prefixed message."""
        self.writer.write(struct.pack(_LENGTH_PREFIX_FORMAT, len(payload)) + payload)
        await self.writer.drain()

    async def read_raw(self) -> bytes:
        """Read one length-prefixed message."""
        return await read_length_prefixed(self.reader, max_size=MAX_HANDSHAKE_MESSAGE_SIZE)

    async def send_hello(
        self,
        *,
        device_id: str | None = None,
        identity_public_key: bytes | None = None,
    ) -> bytes:
        """Send message 1 and remember the exact bytes."""
        private, public = self.key_exchange.generate_key_pair()
        self._ephemeral_private = private
        hello = encode_hello(
            e_i=public,
            n_i=b"\x11" * NONCE_SIZE,
            device_id=device_id or self.device_id,
            identity_public_key=identity_public_key or self.own_identity.public_key,
            transfer_port=self.transfer_port,
            manifest_port=self.manifest_port,
            version=HANDSHAKE_VERSION,
        )
        self.hello_bytes = hello
        await self.send_raw(hello)
        return hello

    async def read_reply(self) -> ReplyMessage:
        """Read message 2 and derive this side's secrets."""
        self.reply = decode_reply(await self.read_raw())
        t2 = transcript_t2(self.hello_bytes, self.reply.body)
        shared_secret = self.key_exchange.derive_shared_secret(
            self._ephemeral_private, self.reply.e_r
        )
        self.secrets = derive_handshake_secrets(
            shared_secret=shared_secret,
            hello=decode_hello(self.hello_bytes),
            reply=self.reply,
            transcript_t2=t2,
        )
        self._t2s = transcript_t2s(t2, self.reply.sig_r)
        return self.reply

    async def send_confirm(
        self,
        *,
        tamper_sig_i: bool = False,
        tamper_mac_i: bool = False,
        raw: bytes | None = None,
    ) -> bytes:
        """Send message 3, optionally corrupted."""
        if raw is not None:
            await self.send_raw(raw)
            return raw
        assert self.secrets is not None
        assert self.reply is not None
        sig_i = self.identity_provider.sign(
            self.own_identity.private_key, signed_initiator(self._t2s)
        )
        if tamper_sig_i:
            sig_i = bytes([sig_i[0] ^ 0xFF]) + sig_i[1:]
        t3 = transcript_t3(self._t2s, self.reply.mac_r)
        t3s = transcript_t3s(t3, sig_i)
        mac_i = confirmation_mac(self.secrets.initiator_confirmation_key, t3s)
        if tamper_mac_i:
            mac_i = bytes([mac_i[0] ^ 0xFF]) + mac_i[1:]
        self.sig_i = sig_i
        self.mac_i = mac_i
        self.t3s = t3s
        payload = encode_confirm(sig_i=sig_i, mac_i=mac_i)
        await self.send_raw(payload)
        return payload

    async def read_final(self) -> FinalMessage:
        """Read message 4."""
        self.final = decode_final(await self.read_raw())
        return self.final

    async def close(self) -> None:
        """Close the connection."""
        self.writer.close()
        with contextlib.suppress(ConnectionError):
            await self.writer.wait_closed()

    def expected_accept_mac(self) -> bytes:
        """Return the ``mac_f`` an accepting responder must send."""
        assert self.secrets is not None
        return confirmation_mac(
            self.secrets.responder_confirmation_key,
            transcript_m4_accept(transcript_final(self.t3s, self.mac_i)),
        )
