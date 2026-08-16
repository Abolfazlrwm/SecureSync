# ADR 0018: A Real X25519 Key-Exchange Handshake

**Status:** Accepted
**Date:** Post-ADR-0017 follow-up

## Context

ADR-0017 named the exact remaining prerequisite for wiring
`TcpTransferTransport` into a real deployment: nothing in this
codebase established the per-session key it needs.
`PycaSessionKeyProvider.derive_session_keys`'s own docstring (added
during the Phase 4-10 audit) flagged the underlying reason a naive
caller would get this wrong: two peers computing from the same shared
secret and salt get the *identical* `(key_1, key_2)` pair back — with
no role convention, both sides would try to encrypt with the same key
instead of complementary ones.

## Decision

**`X25519Handshake`** (`infrastructure/networking/x25519_handshake.py`)
performs the initiator or responder half of a real X25519 exchange
over a real TCP connection: `initiate(host, port)` connects out and
sends `{device_id, salt, public_key}`; `accept(reader, writer)` reads
that, generates its own ephemeral keypair, and replies with
`{device_id, public_key}`. Both sides compute the same ECDH shared
secret and call `derive_session_keys(shared_secret, salt)`, getting
the identical `(key_1, key_2)`.

**The ambiguity is resolved by a fixed role convention:** the
initiator returns `(send=key_1, receive=key_2)`; the responder returns
the swapped `(send=key_2, receive=key_1)`. Verified in this session
over a real socket, not just reasoned about:
`initiator_result.send_key == responder_result.receive_key` and
`initiator_result.receive_key == responder_result.send_key` both hold,
and the two keys are confirmed distinct (real directional separation,
not one key reused both ways).

**`InProcessTransferTransport` and `TcpTransferTransport` were
refactored** to take `send_key`/`receive_key` separately instead of
one shared `key` — matching what a real handshake actually produces.
This is a breaking change to code added in this same integration
effort (ADR-0016/0017), not to any previously-stabilized phase, so it
was made directly rather than deprecated alongside the old signature.
Verified end-to-end in this session: a real handshake's
`HandshakeResult` was fed directly into two `TcpTransferTransport`
instances (no hardcoded key anywhere), and a chunk was uploaded and
downloaded correctly through the unmodified application use cases —
the complete chain from key exchange to encrypted chunk delivery,
proven over real sockets.

**No peer authentication.** A successful handshake proves the other
side completed X25519 correctly — nothing more. It doesn't verify the
peer's claimed `device_id` is who it says it is, and there's no
protection against a machine-in-the-middle substituting its own
keypair during the exchange. This requires a persistent
identity/known-peers store (verifying a peer's long-term public key
against a previously-trusted one, or at minimum trust-on-first-use
with a way to detect a later key change) that doesn't exist in this
codebase — see Consequences.

## Consequences

**Positive**

- The specific ambiguity ADR-0016's docstring warning flagged is now
  resolved with a verified test, not just a documented caveat.
- The full chain — discover a peer, negotiate keys, transfer an
  encrypted chunk — is real and tested end to end for the first time.
  `main.py` wiring (constructing per-peer `TcpTransferTransport`
  instances from `SyncOrchestrator.handle_peer_discovered`, once a
  peer's handshake completes) is now a composition task, not a
  cryptography task.

**Negative / trade-offs accepted**

- No peer authentication, as above — this handshake alone does not
  make SecureSync safe to run on an untrusted network yet. Anyone who
  can connect to the handshake port can complete a valid exchange and
  receive encrypted chunks. A production deployment needs a
  known-peers/trust store layered on top before this is exposed
  beyond a trusted local network.
- No replay or downgrade protection beyond what a fresh salt and
  ephemeral keypair per handshake already provide (confirmed by test:
  repeated handshakes between the same two peers produce different
  keys every time).
- `main.py` still doesn't call any of this — per-peer transport
  construction from `SyncOrchestrator` is the next composition step,
  not addressed here to keep this change reviewable on its own.

## Rejected: skip the send/receive key refactor, keep one shared key

Would have avoided touching `InProcessTransferTransport`/`TcpTransferTransport`,
but a single shared key for both directions is exactly the
"no role convention" failure mode this ADR exists to fix — keeping it
would mean the handshake produces a correct directional pair that the
transports then can't actually use directionally. Fixing the
transports' constructors now, while they're both still recent,
unreleased Phase 11 code, is cheaper than fixing it later.

## Rejected: add peer authentication in this same change

Verifying a peer's long-term identity needs a persistent store this
project doesn't have (Phase 8's `SqliteMetadataRepository` covers file
manifests, not peer identities) and a policy decision (trust-on-first-use?
a pre-shared known-peers list?) that deserves its own deliberate ADR
rather than being folded in here.
