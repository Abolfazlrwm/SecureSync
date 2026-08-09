# ADR 0017: A Real TCP Transport — and Why It Still Isn't Wired Into `main.py`

**Status:** Accepted
**Date:** Post-ADR-0016 follow-up

## Context

ADR-0016 built `InProcessTransferTransport` to prove the crypto and
application-use-case wiring in `UploadChunksUseCase`/`DownloadChunksUseCase`
was correct, but explicitly left "no socket-based `TransferTransport`"
as its one disclosed remaining gap. This ADR closes that specific gap
with `TcpTransferTransport` (`infrastructure/networking/tcp_transport.py`) —
and, just as importantly, is explicit about the *next* gap that
surfaced while building it, rather than papering over it the way
`main.py`'s old `MagicMock` wiring did.

## Decision

**A real TCP transport, verified over real sockets.** `TcpTransferTransport`
implements `TransferTransport` with an actual `asyncio.start_server`
listening socket and a short-lived `asyncio.open_connection` per
outbound chunk. Each connection carries one length-prefixed, AEAD-encrypted
envelope (`core/protocol.py` framing, same as `InProcessTransferTransport`) —
length-prefixing is necessary here because TCP is a byte stream with no
message boundaries of its own, unlike the in-process transport's
already-discrete `asyncio.Queue` items. Verified in this session, not
just reasoned about: two real instances listening on real localhost
ports transferred multiple chunks bidirectionally through the
unmodified `UploadChunksUseCase`/`DownloadChunksUseCase`, and a
receiver with the wrong key correctly got `cryptography.exceptions.InvalidTag`
rather than silently succeeding — both over actual socket I/O, not
an in-memory stand-in.

**No TLS layer added.** Confidentiality and integrity already come
from the same per-message `AeadCipher` encryption
`InProcessTransferTransport` uses — wrapping the socket in TLS on top
would be redundant defense-in-depth, not a missing requirement, and
adds real operational cost (certificate provisioning and rotation)
this project has no mechanism for yet. If mutual TLS becomes a
requirement later (e.g. to authenticate a peer's *identity* rather
than just decrypt its messages), that's a deliberate future decision,
not an oversight here.

**Still not wired into `main.py`, and this time the reason is
different from ADR-0016's.** `TcpTransferTransport` needs a
per-session symmetric key — the same `key: bytes` constructor
parameter `InProcessTransferTransport` takes. Nothing in this codebase
establishes that key between two real, independent processes yet:
`domain/crypto.py`'s `KeyExchangeProvider`/`SessionKeyProvider` and
`core/protocol.py`'s `PacketType.HELLO`/`KEY_EXCHANGE`/`AUTH` values
are all declared but no code anywhere sends or handles those packet
types — there is no handshake implementation to call. Hardcoding a
shared key into `main.py` to make the wiring "complete" would satisfy
the letter of "wire it up" while creating exactly the kind of
misrepresented security posture this project's audit process exists
to catch: a config-baked static key is not the key exchange the
crypto layer's own tests already assume exists.

## Consequences

**Positive**

- The transfer path (chunking → delta → encryption → real socket
  transport) is now fully real end-to-end for any two processes that
  already agree on a key — verified, not assumed.
- The one remaining gap to a fully wired `main.py` is now a single,
  precisely named piece of work — implement the `HELLO`/`KEY_EXCHANGE`/`AUTH`
  handshake using the already-built `PycaKeyExchangeProvider` and
  `core/protocol.py` packet types — rather than an open-ended "make
  the network layer real" task.

**Negative / trade-offs accepted**

- `main.py` still cannot synchronize with a real remote peer today.
  Everything needed exists except the handshake that negotiates the
  key `TcpTransferTransport` requires.
- One connection per chunk, no connection pooling or keep-alive. Fine
  for this ADR's scope (proving the transport is real); a
  high-throughput deployment would want persistent per-peer
  connections, deferred until there's a real workload to measure
  against rather than guessed at now.
- No retry/backoff on a failed `send_chunk` — a connection failure
  propagates as an `OSError` to the caller. Reconnect policy depends
  on decisions the (still unbuilt) handshake and peer-liveness logic
  need to make together, so isn't designed here in isolation.

## Rejected: hardcode a shared key in `main.py` to complete the wiring

Would make `main.py` "use" `TcpTransferTransport`, but the key
wouldn't come from anything resembling real key exchange — every
deployment would trust the same static bytes, defeating the point of
having `KeyExchangeProvider` at all. This is the same category of
problem ADR-0016 fixed (real work standing in for a mock); doing it
here with a fake key instead of a fake use case would be the same
mistake in a different shape.

## Rejected: build the handshake in this same change

The handshake is a genuinely separate piece of work — parsing
`HELLO`/`KEY_EXCHANGE`/`AUTH` packets, running the X25519 exchange,
calling `derive_session_keys` (whose send/receive key-swap ambiguity,
flagged during the Phase 4-10 docstring audit, must be resolved
correctly here specifically), and deciding peer authentication policy
(trust-on-first-use? a known-peers list?). Scoping it into this ADR
would risk rushing exactly the piece of this system with the highest
cost of getting wrong.
