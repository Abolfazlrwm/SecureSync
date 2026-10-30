# Step 1d — Replay Protection (FINAL DESIGN v3)

Status: **approved**, implemented in this step.

This document is the authoritative specification for the v2 SecureSync wire
protocol. It is checked into the repository so that the design survives any
interruption mid-implementation. Where this document and the code disagree, the
code is wrong — except where a section is explicitly marked *deferred*.

---

## 1. Wire frame

Every message is sent as an existing 4-byte length prefix followed by this
frame:

```text
[version:1][direction:1][packet_type:1][session_id:8][nonce:12][ciphertext:n][tag:16]
```

* `version`, `direction`, `packet_type`, `session_id` and `nonce` are
  **plaintext**.
* `ciphertext` is the AEAD encryption of `Packet.encode()` — the full 32-byte
  `PacketHeader` (including `message_id` and `timestamp`) plus the payload.

### Protocol version

`CURRENT_VERSION` is bumped **1 → 2**. The version byte is checked **before**
any decryption: a mismatch raises `UnsupportedVersionError`, which is a clean,
explicit error for peers still running v1. There are **no frame magic bytes**;
the version byte is the first thing on the wire.

> **Breaking change.** v1 and v2 peers cannot interoperate. The v1→v2 break is
> documented in `docs/protocol.md`.

---

## 2. Associated data (AAD)

The AAD is built from the plaintext frame header plus the two device IDs, and
every variable-length field is length-prefixed. There is **no string
concatenation** anywhere in the construction.

```text
[version:1][direction:1][packet_type:1][session_id:8]
[sender_id_len:2][sender_id]
[receiver_id_len:2][receiver_id]
```

* `sender_id` comes from the **looked-up authenticated session**
  (`session.peer_id`) — never from a field inside the packet. An attacker
  cannot claim a different sender by editing the payload, because the payload
  is not what the AAD is built from.
* `receiver_id` is the own device ID at receive time and the peer ID at send
  time.
* `packet_type` is plaintext and part of the AAD. After decryption the inner
  header's `packet_type` must equal the outer one, otherwise the frame is
  rejected.

Length-prefixing is load-bearing: without it, `sender="ab"`, `receiver="cd"`
and `sender="abc"`, `receiver="d"` would produce identical AAD bytes.

---

## 3. Nonce

The nonce is 12 bytes, **deterministic, never random**:

```text
[direction:1][counter:8 big-endian][0x00 0x00 0x00]
```

* The counter equals `header.message_id`.
* **Counter 0 is invalid**; sender counters start at 1.
* Direction is **role-based**, not "outbound/inbound":
  * `0x00` = initiator → responder
  * `0x01` = responder → initiator

The sender sets the direction from its own role. The receiver derives the
expected direction from *its* role and rejects a frame carrying a different
direction **before decrypting**. This is what defeats reflection (A→B replayed
back to A): the replayed frame arrives at A carrying direction `0x00`, but A,
being the initiator, expects `0x01`.

Because the nonce is deterministic, the receiver can recompute what the nonce
*should* be from the plaintext direction and the decrypted header's
`message_id`, and reject any mismatch (`NonceMismatchError`). A random nonce
would make that check impossible and would also allow nonce reuse under a
fixed key.

---

## 4. Key derivation

All derivation uses HKDF. **Every variable-length field is length-prefixed**
(`lp(x)` = 2-byte big-endian length ‖ x); raw concatenation is never used.

```text
master     = HKDF(shared_secret, salt,
                  info = lp("securesync-master-v2")
                       ‖ lp(initiator_ephemeral_pub)
                       ‖ lp(responder_ephemeral_pub))

session_id = first 8 bytes of HKDF(shared_secret, salt,
                  info = lp("securesync-session-id")
                       ‖ lp(initiator_ephemeral_pub)
                       ‖ lp(responder_ephemeral_pub))
             # identical on both sides

i2r_key    = HKDF(master,
                  info = lp("securesync-initiator-to-responder")
                       ‖ lp(initiator_id) ‖ lp(responder_id)
                       ‖ session_id
                       ‖ lp(initiator_ephemeral_pub) ‖ lp(responder_ephemeral_pub))

r2i_key    = HKDF(master,
                  info = lp("securesync-responder-to-initiator")
                       ‖ lp(initiator_id) ‖ lp(responder_id)
                       ‖ session_id
                       ‖ lp(initiator_ephemeral_pub) ‖ lp(responder_ephemeral_pub))
```

Role mapping:

| Role      | send key | receive key |
|-----------|----------|-------------|
| Initiator | `i2r`    | `r2i`       |
| Responder | `r2i`    | `i2r`       |

Required properties (each has a test):

* `A.send_key == B.receive_key`
* `A.send_key != A.receive_key`
* both peers hold the same `{i2r, r2i}` pair
* different `(initiator_id, responder_id)` splits of the *same* concatenated
  bytes derive **different** keys

---

## 5. Session model

A handshake creates a session.

* Sessions are keyed by `session_id` as the **primary** key. Receive-side
  lookup is O(1) from the plaintext frame; there is **no trial decryption**
  across candidate sessions.
* A secondary index `peer_id → [session_id]` supports send-side selection.
* **Multiple concurrent sessions per peer are allowed.**
* A new hello **never** evicts or replaces an existing session. This means a
  replayed signed hello cannot evict a healthy session, and a restarted peer
  can reconnect with a fresh session.
* The "drop hello from a known peer" idea is deliberately **not** implemented:
  it breaks reconnecting after a restart.

### `PeerSession` fields

`peer_id`, `session_id`, `role`, `send_key`, `receive_key`, `transfer_port`,
`manifest_port`, `confirmed`, `created_at`, `last_activity`,
`next_send_counter`, `receive_window`.

### Confirmation (per role)

Transfers are one-way, so "confirmed" is defined per role:

* **Initiator-side** session is confirmed once the responder's signed handshake
  reply is verified.
* **Responder-side** session is confirmed on the first successfully
  authenticated inbound packet.

### Caps and expiry

| Policy | Value |
|---|---|
| `MAX_SESSIONS_PER_PEER` | 8 |
| `MAX_UNCONFIRMED_PER_PEER` | 4 |
| global session cap | configurable (default 256) |
| idle timeout, unconfirmed | 60 s |
| idle timeout, confirmed | 3600 s |
| max key lifetime | 24 h (configurable) |
| `MAX_MESSAGES_PER_KEY` | 2³² |
| `MAX_COUNTER` | 2⁶³ − 1 |

Eviction order: **oldest-created** unconfirmed sessions first (not LRU), then
least-recently-used confirmed sessions. Idle expiry is a **lazy sweep on
access**.

On counter exhaustion or key expiry the sender opens a **new session**;
`CounterExhaustedError` is handled by opening a new session and is never a dead
end.

### Send-side session selection

The sender picks a **confirmed, non-expired, non-exhausted** session. If none
exists it spawns a new handshake.

### Counters

`next_send_counter` starts at 1. The read-and-increment is atomic with **no
`await` between the read and the increment**. A failed send consumes the
counter; a retry takes a new one.

---

## 6. `AntiReplayWindow`

* Fixed-size bitmask (default 128 bits), not an unbounded set.
* Counter 0 is invalid.
* Window state is **per session** and starts fresh with the session.
* `would_accept(counter) -> bool` is **pure** — no mutation. It is used as a
  cheap pre-filter before decryption.
* `accept(counter) -> bool` is a single atomic check-and-set with **no `await`
  inside**. It returns `False` for duplicates and too-old counters; it returns
  `True` and mutates **only** on acceptance.
* There is **no `revoke()`**. Accepting a counter is irreversible — that is
  precisely what makes replay impossible.

---

## 7. Receive order

The order is normative. Steps (a)–(e) are pure; only (f) mutates replay state.

1. **Cheap pre-filters, no state mutation**
   * version check
   * direction check
   * session lookup by `session_id`
   * `window.would_accept(counter from nonce)`
2. **AEAD decrypt/authenticate** using the AAD from §2
3. **Nonce check** — `nonce == derive_nonce(direction, header.message_id)`,
   else `NonceMismatchError`
4. **Packet-type check** — inner `packet_type` must equal the outer one
5. **Timestamp skew** — pure check, configurable `TIMESTAMP_SKEW_MS`
   (default 300000). Clear message, e.g.
   `timestamp skew 420000ms exceeds limit 300000ms`. This is a **secondary**
   defence only; the replay window is primary.
6. **`window.accept()`** — the **only** state mutation, performed **last**,
   after authentication and every other check has passed
7. Mark the responder-side session confirmed and update `last_activity`

Doing (f) last is the whole point: an attacker who forges or tampers with a
frame can never advance the window, so a valid packet cannot be locked out by a
forged high counter.

---

## 8. Deferred to item 1e, and threat-model notes

The following are **explicitly out of scope for 1d** and must be documented as
open items:

* transcript-bound signed handshake
* explicit key-confirmation message
* explicit rekey / teardown signal

Two further notes belong in the threat model:

* Untrusting a peer (item 1f) **must purge every session belonging to that
  peer** — a single surviving session would keep the untrusted peer
  authenticated.
* `version`, `direction`, `packet_type` and `session_id` are **plaintext
  metadata**. They are authenticated (covered by the AEAD tag via the AAD) but
  **not confidential**: a passive observer learns which session and packet type
  a frame belongs to, and can count frames per session.

---

## 9. Required tests

Each test must exercise the real attack, not merely assert that a helper
exists.

### Replay and forgery

* duplicate packet rejected
* out-of-order packet within the window accepted
* too-old packet rejected
* two concurrent identical packets → exactly one accepted
* reflected packet (A→B replayed back to A) rejected
* tampered `message_id` rejected
* tampered `session_id` rejected
* tampered plaintext frame fields (`direction` / `packet_type` / `version`)
  rejected
* an authentic but stale-timestamp packet carrying a **high** counter must
  **not** advance the window

### Session lifecycle

* peer restart / re-hello creates a new session **without** evicting the old one
* replayed hello creates only an **unconfirmed** session; it evicts first and
  never evicts a real session
* initiator pushes N chunks over one session with no reply, and no new
  handshakes are created
* concurrent sends from multiple tasks never reuse a counter/nonce
* session caps, idle expiry and key-lifetime expiry behave as specified

### Compatibility and key schedule

* an old v1 frame gets a clean `UnsupportedVersionError`
* directional-key tests from §4
* regression test for the own-session/port bug: two peers with different
  device IDs each hold their own session, no lookup uses `own_device_id` where
  the peer's session is required, and messages authenticate in both directions
