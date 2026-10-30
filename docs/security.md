# Security

> Status: **Design** — this document specifies the cryptographic design and
> threat model that Phase 6 (End-to-End Encryption) and Phase 4 (Peer
> Discovery / Authentication) implement against. It is treated as a living
> document and revised whenever a security-relevant decision is made
> (each such revision gets an ADR — see `docs/adr/`).

## 1. Design principle

> **SecureSync never implements custom cryptographic primitives.**

Every cryptographic operation is a direct call into
[`cryptography`](https://cryptography.io/) (pyca), which wraps
OpenSSL/BoringSSL. SecureSync's own code is only responsible for *composing*
these primitives correctly (key exchange → key derivation → AEAD encryption
→ nonce management) — never for implementing them.

## 2. Cryptographic building blocks

| Purpose | Primitive | Notes |
|---|---|---|
| Key exchange | X25519 (ECDH) | Per RFC 7748; forms the shared secret between two peers |
| Key derivation | HKDF-SHA256 | Derives per-session symmetric keys from the ECDH shared secret |
| Symmetric encryption | AES-256-GCM (default), ChaCha20-Poly1305 (alternative) | Both are AEAD ciphers — every encrypted packet is also authenticated |
| Peer authentication | Ed25519 signatures over a challenge | Proves possession of the peer's long-term private key |
| Device fingerprint | SHA-256 of the peer's long-term public key | Human-verifiable short form (like SSH host key fingerprints) for out-of-band pairing |
| Password/passphrase (if used for pairing) | Argon2id | Memory-hard KDF, resists GPU/ASIC brute force |

### Why AES-256-GCM *and* ChaCha20-Poly1305

Both are offered behind the same `AeadCipher` port (Strategy pattern, see
`docs/architecture.md` §4): AES-GCM benefits from hardware acceleration
(AES-NI) on most modern CPUs, while ChaCha20-Poly1305 is faster in software
on platforms without AES-NI (e.g. some ARM devices). The negotiated cipher
is agreed during the `HELLO`/`KEY_EXCHANGE` handshake (see
`docs/protocol.md`).

### Nonce management

AEAD security depends entirely on **never reusing a nonce with the same
key**. The v2 frame uses a deterministic 96-bit nonce:

```text
[direction:1][counter:8 big-endian][0x00 0x00 0x00]
```

The counter is the packet's per-session `message_id`, allocated under a
read-and-increment with no `await` in between, so two concurrent sends cannot
be handed the same value. The direction byte is role-based and also appears in
the AAD, so the two directions never share a nonce space even if their counters
coincide. A receiver recomputes the expected nonce and rejects a mismatch.
Counters start at 1; counter 0 is invalid.

### Session keys and key rotation

- Every peer-to-peer session derives fresh symmetric keys via HKDF from the
  ECDH shared secret — long-term identity keys are never used directly to
  encrypt bulk data.
- Each direction has its own key (`i2r` / `r2i`), so the initiator's send key
  is never also the initiator's receive key.
- A session's keys have an absolute lifetime (24 h by default) and a message
  cap (`2**32` messages, counter `2**63 - 1`). When either is reached the
  sender opens a **new session** with a fresh handshake; the old session stays
  valid until it expires, so an in-flight transfer is not cut off. *Deferred:*
  an in-band rekey signal without a new TCP connection (item 1e).

## 3. Threat model

Format follows a STRIDE-style walkthrough, scoped to what SecureSync's
protocol and peer-authorization model are responsible for.

| Threat | Description | Mitigation |
|---|---|---|
| **Replay attack** | Attacker captures and re-sends a previously valid encrypted packet | Per-session fixed-size (128-bit) sliding window over the AEAD counter; the counter is the frame nonce, so a replayed frame is caught by a pure pre-filter before decryption and again by the atomic `accept()` after authentication. The window advances only after every check passes, so a forged high counter cannot lock the sender out |
| **Reflection** | Attacker replays a frame back at the peer that sent it | Direction is role-based (`0x00` initiator→responder, `0x01` responder→initiator) and is both in the AAD and bound into the nonce; the receiver checks it before decrypting, and the two directions use different keys |
| **Man-in-the-middle (MITM)** | Attacker intercepts the key exchange and impersonates both ends | X25519 exchange is bound to long-term Ed25519 identity keys; the resulting device fingerprint must be verified (out-of-band, on first pairing) before a peer is trusted — a MITM cannot produce a matching fingerprint without the real peer's private key |
| **Packet injection** | Attacker sends crafted packets into an established session | AEAD authentication tag fails for any packet not encrypted under the correct session key; the AAD binds the version, direction, packet type, `session_id` and both device IDs, so a frame cannot be redirected into another session |
| **Tampering** | Attacker modifies a packet in transit | Same AEAD guarantee as above — GCM/Poly1305 tags cover the entire ciphertext; the plaintext frame header is authenticated through the AAD, so editing `direction`, `packet_type` or `session_id` breaks verification |
| **Spoofing** | Attacker claims to be a device it isn't | Peer authentication step (Ed25519 signature over a fresh challenge, bound to the handshake salt) required before any file data is exchanged |
| **Denial of service (DoS)** | Attacker floods a peer with connection attempts or oversized packets | `payload_length` is validated against a maximum before allocating a receive buffer; per-message read timeouts; a cap on concurrent inbound connections; a bounded inbound queue; and a **per-source-IP handshake rate limit applied before any X25519/Ed25519 work** |
| **Session-state exhaustion** | Attacker replays hellos to evict healthy sessions | Sessions are capped per peer (8) and per unconfirmed session (4), unconfirmed sessions are evicted oldest-created-first, and a replayed hello cannot downgrade or reset an already-confirmed session |
| **Unauthorized peers** | A technically-valid device tries to sync without the user's consent | New device fingerprints require **explicit user authorization** (CLI prompt / config entry) before any manifest or chunk data is exchanged — trust is opt-in, never automatic |

### 3.1 What the wire reveals

`version`, `direction`, `packet_type` and `session_id` are **plaintext
metadata**: they are authenticated by the AEAD tag (through the AAD) but not
confidential. A passive observer learns which session and packet type a frame
belongs to and can count frames per session. File names, paths and contents
remain inside the encrypted payload.

### 3.2 Deferred to item 1e

A transcript-bound signed handshake, an explicit key-confirmation message and an
explicit rekey/teardown signal are **not implemented yet**. The handshake signs
the salt and the sender's ephemeral public key, not the full transcript.

Concretely, and as disclosed in
[ADR-0027](adr/0027-handshake-transcript-binding-gap.md):

- **`device_id`, `transfer_port` and `manifest_port` are outside the signed
  bytes.** A captured hello can be relabelled, which pollutes the trust store
  (the real peer's identity key gets pinned under an attacker-chosen device ID)
  and lets the responder store attacker-chosen ports for that peer. The
  identity key itself is bound implicitly, so this is not impersonation of the
  peer — but it is not nothing.
- **The responder has no explicit freshness check.** A replayed hello is
  answered with a fresh ephemeral, so it produces a *different* `session_id`
  and cannot resurrect the captured session — but that is a side effect of the
  key schedule, not an enforced property. Replayed hellos still burn session
  slots; the per-source-IP handshake rate limit and the per-peer unconfirmed
  cap bound the damage.
- **No key confirmation**, so a responder commits a session it never learns is
  usable.

`tests/security/test_handshake_replay.py` encodes all three, with the two
malleability probes as strict expected failures until 1e lands.

## 4. Explicitly out of scope (for now)

- Protection against a fully compromised endpoint (malware with local
  filesystem access can always read plaintext files — no sync tool can
  prevent this).
- Formal, third-party cryptographic audit — noted as a prerequisite before
  any "production-ready" claim is made (tracked in `ROADMAP.md`).
- Anonymity / traffic analysis resistance (SecureSync hides file *contents*,
  not the fact that two IPs are syncing with each other).

## 5. Key storage

Long-term identity keys are stored on disk encrypted at rest using a key
derived from a user passphrase via Argon2id. Exact file format and location
are finalized in Phase 6 and documented here at that time.
