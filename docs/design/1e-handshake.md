# 1e — Handshake redesign: transcript binding, freshness and key confirmation

Status: **Amended design v2 — Option B approved with seven amendments integrated.
Commits 1–4b may be implemented against this document; commit 5 (transport wiring
and `CURRENT_VERSION` bump) waits for sign-off.**

Decision recorded on 2026-10-31:

- **Option B — SIGMA-style handshake on `cryptography` only.**
- **Identity hiding is out of scope for 1e** (§10).
- **Rekey** ships as re-running the handshake first; the `REKEY` packet
  (`0x04`) is a follow-up (§4.12).
- **ADR-0028** is reserved for the later security-audit summary (0027 is taken).

Amendments integrated in this revision (all from the 2026-10-31 review):

1. Message 4 (responder → initiator, accept/reject) and the pin/confirm timing
   (§4.5, §4.9, §6).
2. Trust-store pinning only after the whole handshake verifies (§4.9).
3. Domain-separated signature labels, `hmac.compare_digest`, low-order X25519
   rejection (§4.6, §4.10).
4. Strict input validation and typed decoder errors (§4.10).
5. One absolute handshake deadline plus a global handshakes-per-second cap
   (§5, §6.3).
6. SAS defaults to 4 words (44 bits); 8 digits is the explicit alternative;
   ZRTP-style commit-then-reveal recorded for 1f (§7).
7. `SessionStore` refuses a colliding `session_id`; measured benchmark replaces
   the hand-waved "well under a millisecond"; test-only randomness injection and
   published test vectors (§5, §11, §12).

Related documents:

- [`docs/design/1d-replay-protection.md`](1d-replay-protection.md) — the frame,
  key schedule and session model this design composes with.
- [`docs/adr/0027-handshake-transcript-binding-gap.md`](../adr/0027-handshake-transcript-binding-gap.md)
  — the gap this item closes.
- [`docs/adr/0018-key-exchange-handshake.md`](../adr/0018-key-exchange-handshake.md)
  and [`0019`](../adr/0019-peer-authentication-and-trust-on-first-use.md) — the
  handshake and trust-on-first-use decisions being revised.
- [`docs/protocol.md`](../protocol.md) — the current normative wire format.
- [`tests/security/test_handshake_replay.py`](../../tests/security/test_handshake_replay.py)
  — the executable evidence for the gap.

---

## 1. Scope

1e replaces the handshake and must deliver, by design rather than by accident:

1. **Freshness from both sides** — fresh randomness from both peers in every
   handshake, so a captured handshake cannot reproduce a session.
2. **Transcript binding** — every identity field, public key, ephemeral, nonce
   and advertised port is covered by an authenticated value.
3. **Mutual authentication** against the long-term Ed25519 identity.
4. **Explicit key confirmation in both directions**, including a final
   responder→initiator accept/reject message, so the initiator never treats a
   session as usable before the responder has committed to it.
5. **Forward secrecy** — long-term key compromise does not expose past sessions.
6. **Composition with 1d** — the output is still
   `(session_id, role, send_key, receive_key, peer_transfer_port,
   peer_manifest_port)`, so `SecureChannel`, `SessionStore`, the frame and
   `AntiReplayWindow` are unchanged.

Out of scope for 1e: pairing UX and the `pair/trust/untrust` commands (1f, §7),
extra security tests beyond the handshake (1g), and the ADR-0027 /
threat-model-to-test mapping (1h).

---

## 2. Current v2 baseline

The current handshake is a **single msgpack message each way**, length-prefixed
with a 4-byte big-endian prefix (`read_length_prefixed`, bounded by
`MAX_HANDSHAKE_MESSAGE_SIZE`), in
`src/securesync/infrastructure/networking/x25519_handshake.py`.

- Hello: `device_id`, `transfer_port`, `manifest_port`, `salt` (16 B),
  `public_key` (X25519, 32 B), `identity_public_key` (Ed25519, 32 B),
  `signature = Ed25519(salt ‖ public_key)`.
- Reply: same shape, fresh responder ephemeral, `signature =
  Ed25519(request_salt ‖ responder_public_key)`.
- Key schedule: `master = HKDF(ss, salt, lp("securesync-master-v2") ‖ lp(e_i) ‖
  lp(e_r))`; `session_id` and the directional keys follow
  (`session_keys.derive_session_keys`).

Each signature covers **only `salt ‖ its own ephemeral`**. `device_id`, both
public keys and both ports travel outside the signed bytes, there is no
freshness check, no key confirmation and the trust pin is written during
signature verification (before the handshake can still fail). That is ADR-0027.

---

## 3. Options considered

### 3.1 Option A — Noise XX (rejected)

`Noise_XX_25519_ChaChaPoly_SHA256`, three flights (`-> e`, `<- e, ee, s, es`,
`-> s, se`). It would give mutual auth, freshness, transcript binding and
forward secrecy, and `Split()` maps cleanly onto the 1d keys. It was rejected
for two reasons.

**No usable Python library.** Checked 2026-10-31:

| Package | Version | Last release | `requires_python` | Health |
|---|---|---|---|---|
| `noiseprotocol` | 0.3.1 | **2020-03-03** | `~=3.5` | MIT, 222★, 7 open issues, last push 2023-05-09, historically Linux-only CI |
| `noiseframework` | 1.3.0 | 2025-11-25 | `>=3.8` | MIT, **0★**, created 2025-11-16, 0.1.0→1.3.0 in 9 days, single author |
| `noise-py` | 0.0.4 | 2015-10-13 | — | unrelated (`eleme/noise` client) |
| `pynoise` | 3.0.0 | 2025-08-06 | — | libnoise terrain maps |
| `noise` | 1.2.2 | — | — | Perlin noise |
| `snow` | 0.3.1 | 2020-06-05 | — | ServiceNow asyncio client |

There is no maintained, widely-vetted Python Noise implementation.

**Identity-model migration.** Noise authenticates with **static X25519 keys**
(`s` is a DH key), not Ed25519 signatures. Adopting it forces a static X25519
identity, a device ID derived from that key, and re-pinning every peer in the
trust store — or a dual-key model. That is a large, breaking change for no
security property we cannot get with B.

### 3.2 Option B — SIGMA-style (chosen)

A four-message SIGMA construction using only `cryptography`: X25519 ECDH,
Ed25519 signatures, HKDF-SHA256, HMAC-SHA256 and the existing
`length_prefixed`. It keeps Ed25519, `device_id` and the trust store unchanged,
reuses the 1d helpers, and gives explicit key confirmation in both directions.
Its cost is that we implement a small protocol in-tree — stated plainly in §8
and §10.

---

## 4. The v3 handshake (normative)

### 4.1 Conventions

- All integers are **big-endian**.
- `lp(x)` = 2-byte BE length ‖ `x` (`session_keys.length_prefixed`); values
  longer than 65535 bytes are rejected with `HandshakeValidationError`.
- `H = SHA256`.
- `T1 = b"securesync-1e-handshake-v1"` prefixes every hash.
- Each message is framed by the existing 4-byte BE length prefix
  (`read_length_prefixed`); the bytes below are the payload **after** that
  prefix.
- `HANDSHAKE_VERSION = 3`, equal to `CURRENT_VERSION` after 1e.
- The handshake messages are **not** 1d frames. The 1d frame
  (`version|direction|packet_type|session_id|nonce|ciphertext|tag`) starts only
  after the handshake completes.

> **Two separate type namespaces.** The handshake `msg_type` field —
> `0x01 HELLO`, `0x02 REPLY`, `0x03 CONFIRM`, `0x04 FINAL` — exists only inside
> the four pre-session handshake messages. `PacketType` — including
> `REKEY = 0x04` — exists only inside the 1d frame, after the handshake. The
> value `0x04` means `FINAL` in a handshake message and `REKEY` in a frame;
> they never appear in the same context and must not share a decoder.

### 4.2 Message 1 — initiator → responder (unsigned)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | `version` | `0x03`; anything else ⇒ `UnsupportedVersionError` |
| 1 | 1 | `msg_type` | `0x01` |
| 2 | 32 | `e_i` | initiator X25519 ephemeral public key |
| 34 | 32 | `n_i` | initiator nonce from the CSPRNG |
| 66 | 2 | `id_i_len` | uint16 BE |
| 68 | `id_i_len` | `id_i` | initiator `device_id`, UTF-8, 1–64 bytes |
| 68+L | 32 | `id_pub_i` | initiator Ed25519 identity public key |
| 100+L | 2 | `transfer_port_i` | uint16 BE, 1–65535 |
| 102+L | 2 | `manifest_port_i` | uint16 BE, 1–65535 |

Total = **104 + L** bytes. Message 1 carries **no signature**: the initiator
does not yet know `e_r`, so it cannot sign the full transcript (§5 for the DoS
trade-off, §4.6 for why the signature moved to message 3).

### 4.3 Message 2 — responder → initiator

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | `version` | `0x03` |
| 1 | 1 | `msg_type` | `0x02` |
| 2 | 32 | `e_r` | responder X25519 ephemeral public key (fresh) |
| 34 | 32 | `n_r` | responder nonce from the CSPRNG |
| 66 | 2 | `id_r_len` | uint16 BE |
| 68 | Lr | `id_r` | responder `device_id`, UTF-8, 1–64 bytes |
| 68+Lr | 32 | `id_pub_r` | responder Ed25519 identity public key |
| 100+Lr | 2 | `transfer_port_r` | uint16 BE |
| 102+Lr | 2 | `manifest_port_r` | uint16 BE |
| 104+Lr | 64 | `sig_r` | Ed25519 over `lp("securesync-1e-responder-sig") ‖ t2` |
| 168+Lr | 32 | `mac_r` | HMAC-SHA256(`k_r`, `t2s`) — key confirmation |

Total = **200 + Lr** bytes.

### 4.4 Message 3 — initiator → responder

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | `version` | `0x03` |
| 1 | 1 | `msg_type` | `0x03` |
| 2 | 64 | `sig_i` | Ed25519 over `lp("securesync-1e-initiator-sig") ‖ t2s` |
| 66 | 32 | `mac_i` | HMAC-SHA256(`k_i`, `t3s`) — key confirmation |

Total = **98** bytes.

### 4.5 Message 4 — responder → initiator (final, accept/reject)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | `version` | `0x03` |
| 1 | 1 | `msg_type` | `0x04` |
| 2 | 1 | `status` | `0x00` accept, `0x01` reject |
| 3 | 32 | `mac_f` | HMAC-SHA256(`k_r`, `t4`) |

Total = **35** bytes.

`mac_f` binds the final transcript and the status:

```text
t4_accept = H(t_final ‖ lp("securesync-1e-m4-accept"))
t4_reject = H(t2s ‖ lp(m3_raw) ‖ lp("securesync-1e-m4-reject"))
mac_f     = HMAC-SHA256(k_r, t4_accept if status == accept else t4_reject)
```

**Why message 4 exists.** Transfers use concurrent connections, but the
responder only stores the session after verifying message 3. Without message 4,
the initiator's first data frame can reach the responder before the session
exists (`UnknownSessionError`), and if the responder rejects message 3 (for
example a trust-pin mismatch) the initiator never learns. Message 4 is the
responder's explicit commitment: the initiator treats the session as **usable
only after verifying `mac_f`** with `status = accept`.

For a well-formed but invalid message 3 (bad `sig_i`/`mac_i`/pin), the responder
sends `status = reject` with `t4_reject`; the initiator fails regardless of
whether it can verify that MAC. For a malformed message 3, the responder sends a
reject using the raw bytes it received; the initiator treats a non-verifying
reject as a failure.

### 4.6 Transcript and what is signed / MACed

Let `m1` be the full message-1 payload, `m2body` the first `104 + Lr` bytes of
message 2 (everything up to and including `manifest_port_r`), `m3_raw` the full
message-3 payload, and `sk_*` / `id_pub_*` the Ed25519 keys.

```text
t2      = H(T1 ‖ lp(m1) ‖ lp(m2body))          # message 1 + message 2 fields
sig_r   = Ed25519_sign(sk_r, lp("securesync-1e-responder-sig") ‖ t2)
t2s     = H(t2 ‖ lp(sig_r))                    # transcript including sig_r
mac_r   = HMAC-SHA256(k_r, t2s)                # responder key confirmation
t3      = H(t2s ‖ lp(mac_r))
sig_i   = Ed25519_sign(sk_i, lp("securesync-1e-initiator-sig") ‖ t2s)
t3s     = H(t3 ‖ lp(sig_i))
mac_i   = HMAC-SHA256(k_i, t3s)                # initiator key confirmation
t_final = H(t3s ‖ lp(mac_i))                   # SAS material (§7)
t4      = H(t_final ‖ lp("securesync-1e-m4-accept"))   # accept; see §4.5
mac_f   = HMAC-SHA256(k_r, t4)
```

| Value | Covers |
|---|---|
| `sig_r` | `version`, `e_i`, `n_i`, `id_i`, `id_pub_i`, ports_i, `e_r`, `n_r`, `id_r`, `id_pub_r`, ports_r — with the **responder** label |
| `sig_i` | all of the above **plus `sig_r`** — with the **initiator** label |
| `mac_r` | `t2s` |
| `mac_i` | `t3s` |
| `mac_f` | `t_final` (or the reject transcript) and the status |
| session keys | `master`, which mixes `t2` and both nonces (§4.7) |

The distinct signature labels mean a responder signature can never be replayed
as an initiator signature (or vice versa), even if the transcript bytes were
somehow identical. All MAC comparisons use `hmac.compare_digest`, never `==`.

### 4.7 Key schedule

```text
ss         = X25519(e_i_priv, e_r)
master     = HKDF(ss, salt = lp(n_i) ‖ lp(n_r),
                  info = lp("securesync-1e-master") ‖ t2)
k_r        = HKDF(master, lp("securesync-1e-kr"))
k_i        = HKDF(master, lp("securesync-1e-ki"))
session_id = HKDF(master, lp("securesync-1e-sid"), length = 8)
common     = lp(id_i) ‖ lp(id_r) ‖ session_id ‖ lp(e_i) ‖ lp(e_r)
i2r_key    = HKDF(master, lp("securesync-1e-i2r") ‖ common)
r2i_key    = HKDF(master, lp("securesync-1e-r2i") ‖ common)
```

`master` binds `t2` (both messages' fields) and both nonces. `k_r` and `k_i` are
separate confirmation keys, so a confirmation MAC cannot be reflected. The
directional keys follow the 1d shape, so `derive_directional_keys` can be reused
with the new `master` and `session_id`.

### 4.8 Version byte and downgrade protection

The first payload byte is the version. Before parsing anything else the receiver
compares it with `CURRENT_VERSION`; a mismatch raises `UnsupportedVersionError`
(the class already used by the 1d frame decoder) **before** any X25519 or
Ed25519 work. A v2 peer sends a msgpack hello whose first byte is a msgpack type
(`0x8x`/`0xde`), so a v3 receiver rejects it cleanly. v2 and v3 cannot
interoperate; this is a deliberate breaking change.

### 4.9 Pin timing (trust-on-first-use)

The trust pin is written **only after the whole handshake verifies**, never at
signature-verification time:

- **Initiator:** `get_trusted_key(id_r)` is checked after `sig_r` verifies;
  `trust(id_r, id_pub_r)` is called only after `mac_r` **and** message 4
  (`status = accept`, `mac_f` verified).
- **Responder:** `get_trusted_key(id_i)` is checked after `sig_i` verifies;
  `trust(id_i, id_pub_i)` is called only after `sig_i` **and** `mac_i` verify,
  before sending message 4 accept.
- After 1f, the pin is written only after the user confirms the SAS.
- A failed or aborted handshake must leave the trust store untouched. There is a
  test that asserts `trust()` is never called on any failure path.

### 4.10 Input validation and low-order points

Every decoder validates before returning, and raises **only** typed errors
(`HandshakeDecodeError`, `HandshakeValidationError`, `LowOrderPointError`,
`UnsupportedVersionError`):

- `device_id`: 1–64 bytes, strict UTF-8, no Unicode control characters
  (`unicodedata.category(ch) == "Cc"`).
- `transfer_port`, `manifest_port`: integers in **1–65535**.
- `lp()` values longer than 65535 bytes are rejected before encoding.
- A peer whose `device_id` or Ed25519 public key equals our own is rejected
  (`HandshakeValidationError`) — self-connection / reflection.
- X25519 public keys are checked against the **eight known low-order points**
  (the libsodium blacklist); the shared secret is also rejected if it is all
  zeros. This closes the "contributory behaviour" hole where a malicious peer
  forces a predictable secret.

### 4.11 No application data before confirmation

`PeerSession.confirmed` is `False` until the role's confirmation point:

- **Initiator:** after `mac_r` **and** message 4 accept (`mac_f` verified).
- **Responder:** after message 3 verifies (`sig_i` and `mac_i`), before it sends
  message 4 accept.

`SecureChannel.seal` (or the transport wrapper) must refuse to encrypt for an
unconfirmed session. This closes the ADR-0027 item "no key confirmation, so a
responder commits a session it never learns is usable."

### 4.12 Explicit rekey

For 1e, rekey is **re-running the handshake**, which is what 1d already assumes
on counter exhaustion (`CounterExhaustedError` → open a new session). The
`REKEY` packet is a follow-up:

- `PacketType.REKEY = 0x04` (free between `AUTH = 0x03` and
  `FILE_MANIFEST = 0x10`) — a **frame** packet type, distinct from the
  handshake `msg_type` namespace (§4.1).
- The `REKEY` frame is the last frame under the old key; both sides derive
  `master' = HKDF(master, lp("securesync-1e-rekey") ‖ lp(rekey_counter))` and
  re-derive `session_id'`, `i2r'`, `r2i'`.
- `rekey_counter` starts at 1; a stale or out-of-order `REKEY` is rejected.

---

## 5. DoS analysis of the unsigned message 1

Because message 1 is unsigned, the responder cannot verify the initiator before
doing work. Per message 1 it does: rate-limit check (O(1)), parse (O(L)), one
X25519 keypair, one ECDH, one Ed25519 signature and a few HKDF calls.

**Measured on the development machine** (Python 3.13.5, Windows 11
10.0.26300, `cryptography` via miniconda, 20 000 iterations):

| Operation | Measured |
|---|---|
| X25519 keygen | 35.3 µs |
| X25519 ECDH | 35.9 µs |
| Ed25519 sign | 36.2 µs |
| Ed25519 verify | 154.0 µs |
| HKDF-SHA256 (32 B) | 13.7 µs |
| HMAC-SHA256 (64 B) | 7.7 µs |
| **Responder, per message 1** (keygen + ECDH + sign + 2 HKDF + HMAC) | **123.3 µs** |
| **Initiator, per message 2** (verify + HKDF + HMAC) | **~175 µs** |

**Assessment: I agree with moving the signature to message 3, with conditions.**

- Signing message 1 would **not** reduce the responder's cost: it still does
  the same keypair, ECDH and signature. It would only add one Ed25519 verify
  (~154 µs) before responding, while making message 1 replayable and revealing
  the initiator's identity to a passive observer.
- At **123 µs** per message 1, the per-IP limit of 30/60 s costs the responder
  at most **~3.7 ms per minute per IP**; a global cap of 200/s costs at most
  **~25 ms per second** in total. That is negligible.
- The exposure is bounded by the existing per-source-IP limiter
  (`MAX_HANDSHAKES_PER_IP = 30` per 60 s), the existing
  `MAX_CONCURRENT_CONNECTIONS`, a **global handshakes-per-second cap**
  (`MAX_GLOBAL_HANDSHAKES_PER_SECOND = 200`, burst 400), a **half-open cap**
  (`MAX_HALF_OPEN = 64`) and **one absolute deadline for the whole handshake**
  (`HANDSHAKE_DEADLINE_S = 10.0`), not a per-read timeout.
- The responder must **not allocate a `PeerSession`** until message 3 verifies.
  Half-open state (ephemerals, nonces, `master`, `k_r`, `k_i`, transcript,
  deadline) is a transient object bounded by `MAX_HALF_OPEN`.
- Before 1f, trust-on-first-use means unknown devices must be accepted, so the
  rate limiters are the primary defence. After 1f, the responder can reject an
  unknown `device_id` before any crypto.
- Optional later hardening (not 1e): a stateless cookie, as in TLS 1.3 or
  IKEv2, to prove reachability before ECDH.

---

## 6. State machines

### 6.1 Initiator

| State | Entry | On event | Next |
|---|---|---|---|
| `IDLE` | — | `initiate()` | build `m1`, send, `SENT_HELLO` |
| `SENT_HELLO` | `m1` sent | `m2` received | version check, parse, `t2`, verify `sig_r` (responder label + TOFU check, **no pin yet**), derive keys, verify `mac_r` (`compare_digest`), send `m3`, `SENT_CONFIRM` |
| `SENT_CONFIRM` | `m3` sent | `m4` received | version/type check, `status = accept` ⇒ verify `mac_f`, **pin**, `CONFIRMED`; `status = reject` ⇒ `FAILED` |
| any wait state | — | deadline / parse error / bad version / bad signature / TOFU mismatch / bad MAC / low-order point / self-connection | `FAILED` |
| `CONFIRMED` | `m4` verified | application data | send under `i2r_key` |
| any | — | close | `CLOSED` |

The initiator is **confirmed only after message 4 accept**. It must not send
application data before that.

### 6.2 Responder

| State | Entry | On event | Next |
|---|---|---|---|
| `WAIT_HELLO` | — | `m1` received | rate-limit check, version check, parse, validation, (post-1f: known device check), generate `e_r`/`n_r`, ECDH + low-order check, derive keys, `t2`/`sig_r`/`t2s`/`mac_r`, send `m2`, `SENT_REPLY` |
| `SENT_REPLY` | `m2` sent | `m3` received | version/type check, parse, `t3`/`t3s`, verify `sig_i` (initiator label + TOFU check), verify `mac_i` (`compare_digest`), **pin**, store `PeerSession(confirmed=True)`, send `m4` accept, `CONFIRMED` |
| `SENT_REPLY` | — | validation/signature/MAC/pin failure | send `m4` reject, **no pin, no session**, `FAILED` |
| any wait state | — | deadline / parse error | `FAILED` |
| `CONFIRMED` | `m4` sent | application data | send under `r2i_key` |
| any | — | close | `CLOSED` |

The responder is **confirmed after message 3** and sends message 4 as its
commitment. On `FAILED` it discards the transient state and stores no session.

### 6.3 Half-open state, caps, deadline

- `SENT_REPLY` is the half-open state; it counts against `MAX_HALF_OPEN = 64`.
- **One absolute deadline** (`HANDSHAKE_DEADLINE_S = 10.0`) covers the whole
  handshake, not each read. Every wait is clamped to the remaining time.
- **Per-source-IP** limiter (30/60 s) stays in
  `HandshakeServer._handle_connection`, before `accept()` and any crypto.
- **Global** cap: 200 handshakes/s, burst 400, in addition to the per-IP
  limiter.

---

## 7. Pairing / SAS (for 1f)

### 7.1 Derivation

```text
sas_material = H(T1 ‖ b"-sas" ‖ t_final)
```

`t_final` binds both Ed25519 identities, both ephemerals, both nonces, both
signatures and both confirmation MACs.

### 7.2 Display

- **Default: 4 words** from a 2048-word list (11 bits per word, **44 bits**),
  e.g. `correct-horse-battery-staple`.
- **Explicit alternative: 8 decimal digits** (26.6 bits).

The default is 4 words because a short SAS can be ground: an active MITM can
vary its own ephemeral and nonce offline, towards one side, until the resulting
SAS collides with the value it showed the other side. The only bound on that
grind is the handshake deadline, so 26.6 bits (8 digits) is too small for the
default. 44 bits raises the cost by ~2^17.4. The proper fix — **commit-then-
reveal (ZRTP-style)**, where each side commits to its ephemeral before seeing
the other's — is recorded for evaluation in 1f; it removes the offline grind
entirely rather than making it more expensive.

### 7.3 Attempt limits

- `MAX_SAS_ATTEMPTS = 3` failed confirmations per peer per 10 minutes, then the
  peer is locked out until `securesync untrust` and a fresh `pair`.
- `pair` is also rate-limited per source IP, reusing `SourceIpRateLimiter`.
- A failed pairing discards the session and the half-open state; no trust is
  pinned.

`securesync pair` runs the handshake, shows the SAS, waits for confirmation,
then pins the Ed25519 key. `securesync untrust` deletes the pin and purges every
session for that peer via `SessionStore.remove_by_peer`. The current CLI is
misleading: `securesync trust <device>` **deletes** the pin; 1f should split it
into `trust` (confirm/pin) and `untrust` (forget + purge).

---

## 8. Why not TLS 1.3 mutual authentication with pinned self-signed certificates?

Python's `ssl` module supports TLS 1.3, mutual authentication with client
certificates, and certificate pinning. It would mean **zero custom crypto** and
an audited handshake, and it is honestly the better choice for a production
product. We still choose Option B because:

1. **It would discard the 1d work.** The frame, HKDF key schedule,
   `SessionStore`, anti-replay window and their tests are built around a
   handshake that yields `(session_id, role, send_key, receive_key)`. TLS gives
   a byte stream with no such model.
2. **It needs an X.509 identity layer.** The project's identity is an Ed25519
   keypair and a `device_id` pinned in a JSON trust store; TLS wants
   certificates, chain validation, rotation and pinning.
3. **It removes the educational value.** SecureSync exists to demonstrate
   protocol design end to end.
4. **It still needs careful configuration** (verification modes, SNI, ALPN,
   hostname checks) and does not give the `session_id`/role model 1d needs.

The honest conclusion: **TLS 1.3 would be the right engineering choice for a
product; Option B is the right choice for this project**, and the handshake is
therefore a **custom, unaudited protocol** (§10). This section will become an
ADR (§13).

---

## 9. Composition with 1d

Both layers meet at one contract:

```text
HandshakeResult(session_id, role, send_key, receive_key,
                peer_transfer_port, peer_manifest_port)
```

`SecureChannel.seal/open`, `SessionStore.put/get_by_session_id`, the
`[version|direction|packet_type|session_id|nonce|ciphertext|tag]` frame and
`AntiReplayWindow` are untouched. Only `CURRENT_VERSION` moves 2 → 3, and
`UnsupportedVersionError` keeps a v2 peer from being misparsed.

`SessionStore.put()` **refuses a colliding `session_id`** (`SessionIdCollisionError`)
instead of replacing an existing session. Replacing a live session would reset
its anti-replay window and send counter — exactly what a replayed handshake
would want.

---

## 10. Security properties and limitations

| Property | v3 SIGMA-style |
|---|---|
| Mutual authentication | Yes (`sig_r`, `sig_i`, distinct labels) |
| Freshness | Yes (fresh `e_i, e_r, n_i, n_r`; `sig_r` binds message 1) |
| Transcript binding | Yes (`t2`, `t2s`, `t3s`, `t_final`; ids and ports included) |
| Key confirmation | **Explicit both ways** (`mac_r`, `mac_i`, `mac_f`) |
| Identity hiding | **No** — `id_i`/`id_pub_i` are cleartext in message 1. Documented limitation; can be added later by encrypting them under a key derived from `ss`. |
| Forward secrecy | Yes (ephemeral ECDH; static keys only sign) |
| Replay | Replayed message 1 ⇒ fresh `e_r/n_r`, attacker cannot produce `sig_i`/`mac_i`/`mac_f`; full replay fails the transcript |
| Reflection | Direction labels + separate `k_r`/`k_i` + self-connection rejection |
| Malleability | Any byte flip breaks a signature or MAC |
| Downgrade | Version byte checked first and bound into the transcript |
| Low-order / contributory | 8-point blacklist + all-zero shared-secret rejection |
| Pin safety | Pin written only after the whole handshake; failures leave the store untouched |
| Audit status | **Custom, unaudited protocol** (primitives audited; composition not) |

The identity-hiding limitation is accepted for LAN peer-to-peer sync and is
stated in `README.md` and `docs/security.md`.

---

## 11. Implementation plan (small green commits)

Each commit passes the full gate (pytest, ruff, black --check, mypy --strict)
and is pushed before the next begins.

1. **`feat(handshake): add v3 message encoding, validation and known-answer tests`**
   `handshake_messages.py`: encode/decode `m1`–`m4`, version/type checks, the
   validation rules of §4.10, the transcript helpers and the low-order-point
   blacklist. KATs with fixed keys/nonces; a test-only randomness hook.
2. **`feat(handshake): add the v3 key schedule and SAS`**
   `master`/`k_r`/`k_i`/`session_id`/`i2r`/`r2i`, the SAS (4 words default,
   8 digits alternative), tests including a `k_r`/`k_i` reflection test.
3. **`feat(handshake): add the initiator state machine`**
   Four flights, absolute deadline, `UnsupportedVersionError`, TOFU check with
   pin only after message 4, `mac_r`/`mac_f` verification.
4. **`feat(handshake): add the responder state machine`**
   Four flights, half-open cap, absolute deadline, message 4 accept/reject, no
   session or pin before message 3 verifies.
4b. **`test(handshake): property-test the v3 decoders`**
   Hypothesis: arbitrary bytes never crash, only typed errors, no unbounded
   allocation.
5. **`feat(protocol)!: wire the v3 handshake and bump CURRENT_VERSION to 3`**
   `HandshakeResult`, `main.py`, the coordinator, `HandshakeServer`, integration
   tests, v2 → `UnsupportedVersionError`. **Not started until sign-off.**
6. **`test(security): retire the hello-malleability xfails`**
   Remove the two strict `xfail` markers; add replay, MITM, confirmation and
   downgrade tests.
7. **`docs: document the v3 handshake and the custom-protocol caveat`**
   `docs/protocol.md`, `docs/security.md`, `README.md`, the test vectors and the
   ADRs in §13.

---

## 12. Test vectors

Test-only hooks inject fixed ephemerals, nonces and identity keys; the full
handshake is deterministic given those inputs. The published vectors are added
with commit 1 in `docs/design/1e-test-vectors.md`: fixed inputs, exact message
bytes, `t2`/`t2s`/`t3`/`t3s`/`t_final`, signatures, MACs, keys and SAS.
The primitives are additionally anchored to RFC 5869 (HKDF) and RFC 8032
(Ed25519) vectors so a KAT failure points at either the composition or the
primitive.

---

## 13. ADRs, documentation and sign-off

- **ADR-0028 — security-audit summary.** Reserved; 0027 is taken.
- **TLS rationale (§8)** becomes an ADR after 1e (0029 or later), or is folded
  into ADR-0028.
- **README / `docs/security.md`** state: *the handshake is a custom, unaudited
  protocol (SIGMA-style, not TLS or Noise); the primitives are audited, the
  composition is not.*

**Sign-off needed before commit 5.** Commits 1–4b are additive modules and do
not touch the live transport, so they can land first.
