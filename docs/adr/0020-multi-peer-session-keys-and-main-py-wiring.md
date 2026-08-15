# ADR 0020: Multi-Peer Session Keys and Full `main.py` Wiring

**Status:** Accepted
**Date:** Post-ADR-0019 follow-up

## Context

ADR-0017 and ADR-0019 left two things explicitly open: `main.py` still
didn't call `TcpTransferTransport`, `X25519Handshake`, or any of the
Phase 12 crypto work, and `TcpTransferTransport` itself was
constructed with one fixed `(send_key, receive_key)` pair — correct
for talking to exactly one peer, wrong for a device that syncs with
several. A real device needs each peer's *own* negotiated keys, not
one key pair reused for everyone.

## Decision

**`SessionKeyStore`** (`infrastructure/networking/session_key_store.py`)
replaces `TcpTransferTransport`'s fixed key pair with a
`device_id -> PeerSession` registry, where `PeerSession` holds
`send_key`, `receive_key`, *and* `transfer_port`. `send_chunk`/`request_chunks`
already took `peer: Peer` as a parameter (the port's existing
signature), so looking up the right session per call needed no wire-format
change — just a registry lookup keyed by `peer.device_id` instead of
two fixed instance attributes.

**The transfer port is exchanged as part of the handshake itself**,
not derived from any port-offset convention. `X25519Handshake` now
takes `own_transfer_port` and includes it in both the initiator's and
responder's signed messages; `HandshakeResult` carries the peer's
`peer_transfer_port`. This was chosen over a fixed offset (e.g.
"transfer port = discovery port + 1") because it needs no convention
to keep in sync across files and correctly supports a future
deployment where ports aren't sequential. Verified in this session: a
handshake between two instances on arbitrary, non-adjacent ports
correctly taught each side the other's real transfer port, and the
resulting `TcpTransferTransport.send_chunk` connected to that
negotiated port — not the peer's discovery/handshake port.

**`domain/handshake.py`'s `SessionCoordinator` port** keeps
`SyncOrchestrator` (application layer) from depending on
`X25519Handshake` (infrastructure) directly — Clean Architecture's
"application depends only on ports" holds even though a real
handshake is now genuinely wired in.
`infrastructure/networking/x25519_session_coordinator.py`'s
`X25519SessionCoordinator` is the concrete adapter:
`ensure_session(peer)` is idempotent (does nothing if a session
already exists) and initiates a handshake otherwise.
`SyncOrchestrator.handle_peer_discovered` calls it — wrapped in a
`try/except` so one peer's failed handshake (verified in this session:
a simulated `OSError` from `session_coordinator.ensure_session`) is
logged and counted in `stats.errors_encountered` without crashing
discovery of any other peer.

**`main.py` is now fully wired**, verified in this session by actually
running `bootstrap()` (with `zeroconf`/`aiosqlite` stood in for, since
neither is installed in this sandbox — a real environment limitation,
not a code gap) through the point where `orchestrator.start()`
successfully starts real discovery, a real `HandshakeServer` bound to
a real port, and a real `TcpTransferTransport` bound to a real port,
with `download_use_case`/`upload_use_case` no longer `None`. Also
fixed while wiring this: inbound (responder-side) handshake results
need feeding into the *same* `SessionKeyStore` the outbound
(`X25519SessionCoordinator`) side uses — a small `_drain_inbound_handshakes`
background task in `main.py` does this, since `HandshakeServer`
already exposes completed results via its `results` queue and nothing
was draining it into anything before this change.

**`config.network.transfer_port`** (new field, `NetworkConfig`,
default `8082`) is the only new configuration surface added.
`config.network.port` — already the port `MdnsDiscoveryService`
advertises via mDNS — is reused as the handshake port rather than
introducing a third port, since `MdnsDiscoveryService`'s own
`port` parameter is already documented as *"the port this device is
listening on for sync,"* which is exactly what the handshake server
now listens on.

## Consequences

**Positive**

- A device can now genuinely hold simultaneous, independently-keyed
  sessions with multiple peers — the actual requirement for a
  multi-peer sync tool, not just a two-peer demo.
- The transfer port is learned, not guessed — no convention to
  document or get out of sync between the handshake and transport
  code.
- `main.py` no longer has *any* disclosed placeholder in its
  transfer-path wiring; the identity, trust, handshake, session-key
  routing, and transport are all real and running when `bootstrap()`
  executes, verified by actually executing it, not by reading the code
  and assuming.

**Negative / trade-offs accepted**

- `InProcessTransferTransport` (ADR-0016) was deliberately **not**
  refactored to the same `SessionKeyStore` model — it still takes a
  fixed `send_key`/`receive_key` pair. It exists as a same-process
  testing/demonstration tool, not part of the production transfer
  path `main.py` uses, so the inconsistency was accepted rather than
  spending effort making a test-only component multi-peer-capable.
- `main.py`'s wiring couldn't be verified against the *real*
  `zeroconf`/`aiosqlite` packages in this session's sandbox (neither
  is installed, and there's no network access to install them) —
  verification used minimal stand-ins that match the exact method
  signatures these two adapters call, which confirms the *wiring* is
  structurally correct, but real behavior against the actual
  third-party libraries should still be confirmed in an environment
  that has them installed before relying on this in production.
- No connection retry if a handshake or transfer connection fails
  transiently — a dropped connection surfaces as a logged error and
  that peer is simply not synced with until the next discovery
  event notices it's still online. Real retry/backoff policy is
  deferred, same as ADR-0017 already deferred it for the transport
  layer alone.

## Rejected: derive the transfer port from a fixed offset convention

Simpler to implement (no handshake payload change) but fragile —
every place that computes a peer's transfer port would need the exact
same offset constant, and a future deployment with non-sequential
ports would have no way to express that. Exchanging the real port
value during the handshake — a channel that already exists and is
already authenticated — has no real downside once the handshake
itself supports arbitrary payload fields.

## Rejected: give `TcpTransferTransport` its own internal handshake logic

Would keep `main.py`'s wiring simpler (fewer objects to construct) but
merges two genuinely separate concerns — moving encrypted bytes, and
negotiating the keys to encrypt them with — into one class, making
each harder to test in isolation. Keeping `SessionCoordinator` and
`TcpTransferTransport` separate, sharing only the `SessionKeyStore`,
is what let both be verified independently in this session (the
transport with fixed test keys in ADR-0017/0018, the handshake and
its authentication in isolation in ADR-0019) before verifying them
together here.
