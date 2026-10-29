"""Bounded, time-limited length-prefixed message reads for the TCP adapters.

Every untrusted byte that arrives over a socket in this project is framed
as a 4-byte big-endian length prefix followed by that many payload bytes
(see ``X25519Handshake._read_message``,
``TcpManifestExchangeTransport._read_message`` and
``TcpTransferTransport._read_envelope``). That framing is also the oldest
denial-of-service surface in the protocol: a peer can send a length prefix
claiming a multi-gigabyte body and stall or exhaust the receiver while it
waits to read (or tries to buffer) that many bytes, or it can open a
connection and never finish a message (slowloris).

This module is the single place that turns those two attacks into a
rejected message:

* ``read_length_prefixed`` refuses any declared length above ``max_size``
  *before* reading a single body byte, so a 4-byte prefix cannot make the
  receiver allocate (or wait to read) an unbounded buffer;
* it wraps each read in ``asyncio.wait_for`` so a connection that cannot
  deliver a complete message within ``MESSAGE_READ_TIMEOUT`` is dropped
  instead of pinning a task and a socket indefinitely.

The resource ceilings for the listening servers (concurrent connections,
inbound queue depth) live here too, so they are configured in one place
rather than re-derived in each adapter.
"""

from __future__ import annotations

import asyncio
import struct
from typing import Final

from securesync.core.protocol import ProtocolError

_LENGTH_PREFIX_FORMAT = ">I"
LENGTH_PREFIX_SIZE: Final = struct.calcsize(_LENGTH_PREFIX_FORMAT)  # 4 bytes

#: A handshake message is tiny (two ephemeral keys, two Ed25519 public
#: keys, a salt, a signature, and a device id — well under a kilobyte).
#: Pre-authentication, the tighter the ceiling the better, so a peer
#: cannot make us buffer an arbitrary payload before we even know who it
#: is. 64 KiB leaves enormous headroom for the real message.
MAX_HANDSHAKE_MESSAGE_SIZE: Final = 64 * 1024

#: A transport or manifest envelope carries one AEAD-encrypted chunk
#: (nonce + tag + ciphertext) plus msgpack framing. The chunk itself is
#: bounded by ``PushLimits.max_chunk_size`` (64 MiB), so 128 MiB gives
#: comfortable headroom for the largest legitimate message while still
#: being a hard ceiling far below "unbounded".
MAX_MESSAGE_SIZE: Final = 128 * 1024 * 1024

#: Per-read deadline in seconds. A peer that cannot deliver a complete
#: message within this window is stalling on purpose or is gone; either
#: way we drop the connection rather than hold a task and a socket. This
#: is a DoS defense, not a liveness check, so it is intentionally
#: generous; tune down only if your links are fast.
MESSAGE_READ_TIMEOUT: Final = 30.0

#: Most P2P deployments talk to a handful of peers. Capping concurrent
#: inbound connections stops one peer (or a small fleet) from opening
#: thousands of sockets and pinning that many handler tasks.
MAX_CONCURRENT_CONNECTIONS: Final = 256

#: The inbound transport queues decrypted envelopes for the consumer
#: coroutines to drain. Bounding it stops a peer that floods envelopes
#: from growing that queue without limit; when full, the newest envelope
#: is dropped and logged.
INBOX_MAX_SIZE: Final = 4096


class OversizedMessageError(ProtocolError):
    """A peer declared a message length larger than the configured maximum."""


class MessageReadTimeoutError(ProtocolError):
    """A peer did not deliver a complete message within ``MESSAGE_READ_TIMEOUT``."""


async def read_length_prefixed(
    reader: asyncio.StreamReader,
    *,
    max_size: int,
    read_timeout: float = MESSAGE_READ_TIMEOUT,
) -> bytes:
    """Read one length-prefixed message, refusing oversized or stalled reads.

    Args:
        reader: The stream to read from.
        max_size: Maximum acceptable declared message length. Lengths
            above this raise :class:`OversizedMessageError` *before* any
            body byte is read, so the prefix alone cannot drive an
            unbounded allocation or read.
        read_timeout: Maximum seconds to wait for the prefix and,
            separately, for the body. Applied per read.

    Returns:
        The message body bytes (the payload after the length prefix).

    Raises:
        OversizedMessageError: If the declared length exceeds ``max_size``.
        MessageReadTimeoutError: If the prefix or body read does not
            complete within ``read_timeout``.
        asyncio.IncompleteReadError: If the connection closes before the
            declared bytes arrive. Surfaced unchanged so callers can log
            it as a dropped connection.
    """
    try:
        prefix = await asyncio.wait_for(reader.readexactly(LENGTH_PREFIX_SIZE), read_timeout)
    except TimeoutError as exc:
        raise MessageReadTimeoutError("timed out reading message length") from exc

    (length,) = struct.unpack(_LENGTH_PREFIX_FORMAT, prefix)
    if length > max_size:
        raise OversizedMessageError(
            f"declared message length {length} exceeds maximum {max_size}"
        )

    try:
        return await asyncio.wait_for(reader.readexactly(length), read_timeout)
    except TimeoutError as exc:
        raise MessageReadTimeoutError("timed out reading message body") from exc
