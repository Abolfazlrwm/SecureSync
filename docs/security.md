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
key**. SecureSync's plan: a 96-bit nonce per packet, constructed as a
per-session random prefix concatenated with the packet's monotonically
increasing `message_id` counter — this makes nonce reuse structurally
impossible within a session without an actual protocol bug, rather than
relying on randomness alone.

### Session keys and key rotation

- Every peer-to-peer session derives fresh symmetric keys via HKDF from the
  ECDH shared secret — long-term identity keys are never used directly to
  encrypt bulk data.
- Session keys are rotated after a configurable data volume or time
  threshold is crossed (both are configurable — see
  `docs/configuration.md`), via a fresh key-exchange round embedded in the
  session, without dropping the underlying TCP connection.

## 3. Threat model

Format follows a STRIDE-style walkthrough, scoped to what SecureSync's
protocol and peer-authorization model are responsible for.

| Threat | Description | Mitigation |
|---|---|---|
| **Replay attack** | Attacker captures and re-sends a previously valid encrypted packet | Per-session monotonic `message_id`; receiver rejects any ID already seen or outside the current window; AEAD nonce is derived from `message_id`, so a replayed packet also fails nonce-reuse assumptions |
| **Man-in-the-middle (MITM)** | Attacker intercepts the key exchange and impersonates both ends | X25519 exchange is bound to long-term Ed25519 identity keys; the resulting device fingerprint must be verified (out-of-band, on first pairing) before a peer is trusted — a MITM cannot produce a matching fingerprint without the real peer's private key |
| **Packet injection** | Attacker sends crafted packets into an established session | AEAD authentication tag fails for any packet not encrypted under the correct session key; the packet is dropped before reaching application logic |
| **Tampering** | Attacker modifies a packet in transit | Same AEAD guarantee as above — GCM/Poly1305 tags cover the entire ciphertext |
| **Spoofing** | Attacker claims to be a device it isn't | Peer authentication step (`AUTH` packet, Ed25519 signature over a fresh challenge) required before any file data is exchanged |
| **Denial of service (DoS)** | Attacker floods a peer with connection attempts or oversized packets | `payload_length` is validated against a maximum before allocating a receive buffer; per-peer rate limiting; exponential backoff on repeated auth failures from the same source |
| **Unauthorized peers** | A technically-valid device tries to sync without the user's consent | New device fingerprints require **explicit user authorization** (CLI prompt / config entry) before any manifest or chunk data is exchanged — trust is opt-in, never automatic |

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
