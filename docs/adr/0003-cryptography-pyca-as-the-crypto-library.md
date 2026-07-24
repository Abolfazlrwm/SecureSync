# ADR 0003: `cryptography` (pyca) as the Sole Cryptographic Library

**Status:** Accepted
**Date:** Phase 0

## Context

SecureSync needs X25519 key exchange, AES-256-GCM and ChaCha20-Poly1305
AEAD ciphers, Ed25519 signatures, and Argon2id key derivation. The project
must never implement cryptographic primitives itself (stated as a hard
constraint from the outset).

Candidates considered: [`cryptography`](https://cryptography.io/) (pyca),
`PyNaCl` (libsodium bindings), and hand-written implementations (rejected
outright per the constraint above).

## Decision

Use `cryptography` (pyca) as the exclusive source of cryptographic
primitives.

## Consequences

**Positive**
- Maintained by a dedicated security-focused team, wraps
  OpenSSL/BoringSSL — receives security patches on the same cadence as
  those upstream projects.
- Single library covers every primitive SecureSync needs (X25519, AES-GCM,
  ChaCha20-Poly1305, Ed25519), avoiding the complexity of mixing two
  cryptographic libraries with different API conventions and trust
  assumptions.
- Widely used across the Python ecosystem — well understood by reviewers
  and contributors.

**Negative / trade-offs accepted**
- `PyNaCl` (libsodium) has an arguably more misuse-resistant API for some
  operations (e.g. combined nonce+ciphertext helpers) — SecureSync
  compensates with its own thin, carefully reviewed nonce-management layer
  documented in `docs/security.md`, which becomes the single place nonce
  correctness is verified and tested.

## Rejected: hand-rolled cryptography

Not seriously considered — implementing cryptographic primitives from
scratch is explicitly out of scope for this project regardless of
theoretical performance or educational appeal; the risk of subtle,
catastrophic implementation bugs is not worth taking for a project that
intends to actually protect user data.
