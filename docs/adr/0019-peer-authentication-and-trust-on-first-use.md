# ADR 0019: Peer Authentication and Trust-on-First-Use

**Status:** Accepted
**Date:** Post-ADR-0018 follow-up

## Context

ADR-0018 built a real X25519 handshake but explicitly disclosed one
gap: *"a successful handshake only proves the other side completed
X25519 correctly, not that it is who it claims to be."* Nothing
verified a peer's claimed `device_id` corresponded to any specific,
consistent identity across handshakes — a second party could claim to
be an already-known `device_id` and the original handshake code would
accept it just as readily as the real one.

## Decision

**A separate, persistent Ed25519 identity per device**
(`domain/identity.py`'s `IdentityProvider` port,
`infrastructure/crypto/ed25519_identity_provider.py`'s
`Ed25519IdentityProvider` adapter). Deliberately a different key type
and lifecycle from the X25519 handshake keys: X25519 keys are
ephemeral (fresh per handshake, for forward secrecy) and can't sign
anything; Ed25519 keys are generated once, persisted to disk
(`identity.private`/`identity.public`, private key file permissions
restricted to owner where the platform supports it — verified: `0o600`
on this session's Linux sandbox), and exist specifically to sign.

**Each handshake message is now signed.** Both `initiate` and `accept`
sign `salt + ephemeral_public_key` with the sender's persistent
Ed25519 private key and include the signature plus the sender's
identity public key in the message. The receiver verifies the
signature before proceeding — proving the message came from whoever
holds that specific private key and wasn't tampered with in transit.

**Trust-on-first-use (TOFU) via `TrustedPeerRepository`**
(`domain/identity.py`'s port, `infrastructure/networking/file_trusted_peer_repository.py`'s
JSON-file, atomically-written adapter). The *first* handshake with a
given `device_id` pins its presented identity public key; every
subsequent handshake claiming that `device_id` must present the same
key, or `PeerIdentityMismatchError` is raised and the handshake is
refused. Verified end to end in this session: a genuine repeat
handshake with the same on-disk identity succeeds; a second party
claiming the *same* `device_id` with a *different* identity is
rejected — the responder's `HandshakeServer` publishes no result for
it, and the connection is dropped before completing.

## Consequences

**Positive**

- Real protection against a straightforward impersonation attempt:
  claiming someone else's `device_id` without their private key no
  longer works, verified with an actual mismatched-identity handshake
  attempt in this session.
- Key rotation is at least *detectable*: if a genuinely-trusted peer's
  identity key ever changes (new install, lost key, or an attack), the
  next handshake fails loudly instead of silently accepting a new key.

**Negative / trade-offs accepted**

- **This is TOFU, not full PKI.** The *very first* handshake with a
  `device_id` is trusted unconditionally — if an attacker's message
  reaches a peer before the real device's first-ever handshake, the
  attacker's key gets pinned instead. There is no out-of-band identity
  verification step (e.g., comparing fingerprints over a separate
  channel) in this codebase yet.
- **No recovery path for legitimate key rotation.** A device that
  loses its `identity.private` file (disk wipe, reinstall) and
  generates a new one will be permanently rejected by every peer that
  trusted its old key, with no distinction from an actual attack. A
  real deployment needs either a manual "forget this peer" operation
  or a signed key-rotation protocol — neither exists yet.
- **The trust store itself is unauthenticated local state.** Anyone
  with filesystem access to `trusted_peers.json` can edit it directly,
  bypassing TOFU entirely. This is consistent with this codebase's
  general assumption (shared with `identity.private`'s file
  permissions) that the local machine itself is trusted; protecting
  against a compromised local machine is out of scope.

## Rejected: skip authentication, ship the handshake as-is

Was ADR-0018's own explicitly disclosed gap — proceeding without
addressing it would leave `X25519Handshake` cryptographically sound
but practically meaningless as an authentication mechanism: any
process that can reach the handshake port could claim any `device_id`.

## Rejected: full certificate-based PKI with a trusted root

Would solve TOFU's first-contact weakness, but requires a certificate
authority or manual cross-signing process this project has no
infrastructure for and no clear owner for (who runs the CA for a
peer-to-peer sync tool?). TOFU is the standard, pragmatic middle
ground used by comparable tools (e.g. SSH's `known_hosts`) and was
chosen for the same reason: it's real protection against passive
network attackers without requiring infrastructure this project
doesn't have.
