# 1e — Handshake redesign: transcript binding, freshness and key confirmation

Status: **Amended design — Option B approved, awaiting sign-off. No code.**

Decision recorded on 2026-10-31:

- **Option B — SIGMA-style handshake on `cryptography` only** is chosen.
- **Identity hiding is out of scope for 1e** and is documented as a limitation
  (§10).
- **Rekey** ships as re-running the handshake first; the `REKEY` packet
  (`0x04`) is a follow-up (§4.9).
- **ADR-0028** is reserved for the later security-audit summary (0027 is
  taken by the transcript-binding gap).

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

1. **Freshness from both sides** — every handshake mixes fresh randomness from
   both peers into the key schedule, so a captured handshake cannot reproduce a
   session.
2. **Transcript binding** — every identity field, public key, ephemeral, nonce
   and advertised port is covered by an authenticated value.
3. **Mutual authentication** against the long-term Ed25519 identity.
4. **Explicit key confirmation** — no application data before the peer proves it
   derived the same keys.
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
freshness check and no key confirmation. That is ADR-0027. The replay tests show
a replayed hello does not currently reproduce a session — but only because the
responder happens to draw a fresh ephemeral, not because anything enforces it.

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

A three-message SIGMA construction using only `cryptography`: X25519 ECDH,
Ed25519 signatures, HKDF-SHA256, HMAC-SHA256 and the existing
`length_prefixed`. It keeps Ed25519, `device_id` and the trust store unchanged,
reuses the 1d helpers, and gives explicit key confirmation. Its cost is that we
implement a small protocol in-tree — stated plainly in §8 and §10.

---

## 4. The v3 handshake (normative)

### 4.1 Conventions

- All integers are **big-endian**.
- `lp(x)` = 2-byte BE length ‖ `x` (`session_keys.length_prefixed`).
- `H = SHA256`.
- `T1 = b"securesync-1e-handshake-v1"` prefixes every hash and signature.
- Each message is framed by the existing 4-byte BE length prefix
  (`read_length_prefixed`); the bytes below are the payload **after** that
  prefix.
- `HANDSHAKE_VERSION = 3`, equal to `CURRENT_VERSION` after 1e.
- The handshake messages are **not** 1d frames. The 1d frame
  (`version|direction|packet_type|session_id|nonce|ciphertext|tag`) starts only
  after the handshake completes.

### 4.2 Message 1 — initiator → responder (unsigned)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | `version` | `0x03`; anything else ⇒ `UnsupportedVersionError` |
| 1 | 1 | `msg_type` | `0x01` |
| 2 | 32 | `e_i` | initiator X25519 ephemeral public key |
| 34 | 32 | `n_i` | initiator nonce from the CSPRNG |
| 66 | 2 | `id_i_len` | uint16 BE |
| 68 | `id_i_len` | `id_i` | initiator `device_id`, UTF-8 |
| 68+L | 32 | `id_pub_i` | initiator Ed25519 identity public key |
| 100+L | 2 | `transfer_port_i` | uint16 BE |
| 102+L | 2 | `manifest_port_i` | uint16 BE |

Total = **104 + L** bytes. Message 1 carries **no signature**: the initiator
does not yet know `e_r`, so it cannot sign the full transcript (see §5 for the
DoS trade-off and §4.5 for why the signature moved to message 3).

### 4.3 Message 2 — responder → initiator

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | `version` | `0x03` |
| 1 | 1 | `msg_type` | `0x02` |
| 2 | 32 | `e_r` | responder X25519 ephemeral public key (fresh) |
| 34 | 32 | `n_r` | responder nonce from the CSPRNG |
| 66 | 2 | `id_r_len` | uint16 BE |
| 68 | Lr | `id_r` | responder `device_id`, UTF-8 |
| 68+Lr | 32 | `id_pub_r` | responder Ed25519 identity public key |
| 100+Lr | 2 | `transfer_port_r` | uint16 BE |
| 102+Lr | 2 | `manifest_port_r` | uint16 BE |
| 104+Lr | 64 | `sig_r` | Ed25519 over `t2` (§4.5) |
| 168+Lr | 32 | `mac_r` | HMAC-SHA256(`k_r`, `t2s`) — key confirmation |

Total = **200 + Lr** bytes.

### 4.4 Message 3 — initiator → responder

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | `version` | `0x03` |
| 1 | 1 | `msg_type` | `0x03` |
| 2 | 64 | `sig_i` | Ed25519 over `t2s` (§4.5) |
| 66 | 32 | `mac_i` | HMAC-SHA256(`k_i`, `t3s`) — key confirmation |

Total = **98** bytes.

### 4.5 Transcript and what is signed / MACed

Let `m1` be the full message-1 payload, `m2body` the first `104 + Lr` bytes of
message 2 (everything up to and including `manifest_port_r`), and `sk_*` /
`id_pub_*` the Ed25519 keys.

```text
t2      = H(T1 ‖ lp(m1) ‖ lp(m2body))          # message 1 + message 2 fields
sig_r   = Ed25519_sign(sk_r, t2)               # responder authenticates the transcript
t2s     = H(t2 ‖ lp(sig_r))                    # transcript including sig_r
mac_r   = HMAC-SHA256(k_r, t2s)                # responder key confirmation
t3      = H(t2s ‖ lp(mac_r))
sig_i   = Ed25519_sign(sk_i, t2s)              # initiator signs the full transcript
t3s     = H(t3 ‖ lp(sig_i))
mac_i   = HMAC-SHA256(k_i, t3s)                # initiator key confirmation
t_final = H(t3s ‖ lp(mac_i))                   # SAS material (§7)
```

| Value | Covers |
|---|---|
| `sig_r` | `version`, `e_i`, `n_i`, `id_i`, `id_pub_i`, ports_i, `e_r`, `n_r`, `id_r`, `id_pub_r`, ports_r |
| `sig_i` | all of the above **plus `sig_r`** |
| `mac_r` | `t2s` (the whole transcript including `sig_r`) |
| `mac_i` | `t3s` (the whole transcript including `sig_i`) |
| session keys | `master`, which mixes `t2` and both nonces (§4.6) |

Every field the session depends on is inside an authenticated value. In
particular `device_id` and both ports are now in the transcript, which retires
the two strict-`xfail` malleability tests
(`test_relabelled_device_id_is_rejected`,
`test_relabelled_ports_are_rejected`).

### 4.6 Key schedule

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

`master` binds `t2` (both messages' fields) and both nonces, so the keys depend
on the whole transcript. `k_r` and `k_i` are separate confirmation keys, which
prevents reflection of a confirmation MAC. The directional keys follow the 1d
shape, so `derive_directional_keys` can be reused with the new `master` and
`session_id`.

### 4.7 Version byte and downgrade protection

The first payload byte is the version. Before parsing anything else the receiver
compares it with `CURRENT_VERSION`; a mismatch raises `UnsupportedVersionError`
(the class already used by the 1d frame decoder) **before** any X25519 or
Ed25519 work.

A v2 peer sends a msgpack hello whose first byte is a msgpack type
(`0x8x`/`0xde`), so a v3 receiver rejects it cleanly. v2 and v3 cannot
interoperate; this is a deliberate breaking change, the same as the v1→v2 frame
break. The version is also inside `t2`/`t2s`, so a downgrade attempt that
somehow reached the transcript would fail the signature.

### 4.8 No application data before confirmation

`PeerSession.confirmed` is `False` until the role's confirmation point:
the initiator after `mac_r` (message 2), the responder after message 3.
`SecureChannel.seal` (or the transport wrapper) must refuse to encrypt for an
unconfirmed session. This closes the ADR-0027 item "no key confirmation, so a
responder commits a session it never learns is usable."

### 4.9 Explicit rekey

For 1e, rekey is **re-running the handshake**, which is exactly what 1d already
assumes on counter exhaustion (`CounterExhaustedError` → open a new session).
The `REKEY` packet is a follow-up:

- `PACKET_REKEY = 0x04` (free between `AUTH = 0x03` and
  `FILE_MANIFEST = 0x10`).
- The `REKEY` frame is the last frame under the old key; both sides then derive
  `master' = HKDF(master, lp("securesync-1e-rekey") ‖ lp(rekey_counter))` and
  re-derive `session_id'`, `i2r'`, `r2i'`.
- `rekey_counter` starts at 1 and increments per rekey; a stale or out-of-order
  `REKEY` is rejected.

---

## 5. DoS analysis of the unsigned message 1

Because message 1 is unsigned, the responder cannot verify the initiator before
doing work. Per message 1 it does: rate-limit check (O(1)), parse (O(L)), one
X25519 keypair, one ECDH, one Ed25519 signature and a few HKDF calls — well
under a millisecond on a modern CPU.

**Assessment: I agree with moving the signature to message 3, with conditions.**

- Signing message 1 would **not** reduce the responder's crypto cost: it still
  does the same keypair, ECDH and signature. It would only let the responder run
  one extra Ed25519 *verify* before responding — a marginal saving — while
  making message 1 replayable and revealing the initiator's identity to a
  passive observer. So the unsigned message 1 is the better trade.
- The exposure is bounded by the existing per-source-IP limiter
  (`MAX_HANDSHAKES_PER_IP = 30` per 60 s), the existing
  `MAX_CONCURRENT_CONNECTIONS`, and two new limits: a **half-open cap**
  (`MAX_HALF_OPEN`, suggested 64) and a **handshake timeout**
  (`HANDSHAKE_TIMEOUT_S`, suggested 10 s).
- The responder must **not allocate a `PeerSession`** until message 3 verifies.
  The half-open state (ephemerals, nonces, `master`, `k_r`, `k_i`, transcript,
  deadline) is a transient object bounded by `MAX_HALF_OPEN`.
- Before 1f, trust-on-first-use means unknown devices must be accepted, so the
  rate limiter is the primary defence. After 1f, the responder can reject an
  unknown `device_id` before any crypto.
- Optional later hardening (not in 1e): a stateless cookie, as in TLS 1.3 or
  IKEv2, to make the responder prove reachability before doing ECDH. It costs a
  round-trip and is not needed while the limiter holds.

---

## 6. State machines

### 6.1 Initiator

| State | Entry | On event | Next |
|---|---|---|---|
| `IDLE` | — | `initiate()` | build `m1`, send, `SENT_HELLO` |
| `SENT_HELLO` | `m1` sent | `m2` received | check version, parse, compute `t2`, verify `sig_r` (Ed25519 + TOFU pin), derive `master`/`k_r`/`k_i`/keys, verify `mac_r`, send `m3`, `CONFIRMED` |
| `SENT_HELLO` | — | timeout / parse error / bad version / bad `sig_r` / TOFU mismatch / bad `mac_r` | `FAILED` |
| `CONFIRMED` | `m3` sent | application data | send under `i2r_key` |
| any | — | close | `CLOSED` |

The initiator is **confirmed after `mac_r`** (message 2). It may send
application data once `m3` is sent.

### 6.2 Responder

| State | Entry | On event | Next |
|---|---|---|---|
| `WAIT_HELLO` | — | `m1` received | rate-limit check, version check, parse, (post-1f: known device check), generate `e_r`/`n_r`, ECDH, derive `master`/`k_r`/`k_i`, compute `t2`/`sig_r`/`t2s`/`mac_r`, send `m2`, `SENT_REPLY` |
| `SENT_REPLY` | `m2` sent | `m3` received | check version, parse, compute `t3`/`t3s`, verify `sig_i` (Ed25519 + TOFU pin), verify `mac_i`, derive keys, store `PeerSession(confirmed=True)`, `CONFIRMED` |
| `SENT_REPLY` | — | timeout / parse error / bad `sig_i` / TOFU mismatch / bad `mac_i` | `FAILED` |
| `CONFIRMED` | session stored | application data | send under `r2i_key` |
| any | — | close | `CLOSED` |

The responder is **confirmed after message 3**. On `FAILED` it discards the
transient state and stores no session.

### 6.3 Half-open state, caps and timeouts

- `SENT_REPLY` is the half-open state. It counts against `MAX_HALF_OPEN`; a new
  message 1 over the cap is refused before any crypto.
- Each wait state has `HANDSHAKE_TIMEOUT_S` (suggested 10 s); on expiry the
  connection is closed and the transient state dropped.
- The per-source-IP limiter stays exactly where 1d put it: in
  `HandshakeServer._handle_connection`, before `accept()` and before any
  X25519/Ed25519 work.

---

## 7. Pairing / SAS (for 1f)

### 7.1 Derivation

```text
sas_material = H(T1 ‖ b"-sas" ‖ t_final)
```

`t_final` already binds both Ed25519 identities, both ephemerals, both nonces,
both signatures and both confirmation MACs, so a matching SAS proves no MITM.

### 7.2 Display

- Default: **8 decimal digits**, `int.from_bytes(sas_material[:8], "big") %
  100_000_000`, zero-padded. That is 26.6 bits.
- Recommended if the UI allows: **4 words** from a 2048-word list (11 bits per
  word, 44 bits), which is materially stronger against an online guess.

### 7.3 Attempt limits

- `MAX_SAS_ATTEMPTS = 3` failed confirmations per peer per 10 minutes, then the
  peer is locked out until `securesync untrust` and a fresh `pair`.
- `pair` is also rate-limited per source IP, reusing `SourceIpRateLimiter`.
- A failed pairing discards the session and the half-open state; no trust is
  pinned.

`securesync pair` runs the handshake, shows the SAS, waits for confirmation,
then pins the Ed25519 key. `securesync untrust` deletes the pin and purges every
session for that peer via the existing `SessionStore.remove_by_peer`. Note the
current CLI is misleading: `securesync trust <device>` currently **deletes** the
pin; 1f should split it into `trust` (confirm/pin) and `untrust`
(forget + purge).

---

## 8. Why not TLS 1.3 mutual authentication with pinned self-signed certificates?

Python's `ssl` module supports TLS 1.3, mutual authentication with client
certificates, and certificate pinning. Using it would mean **zero custom
crypto** and an audited handshake. It is, honestly, the better choice for a
production product. We still choose Option B because:

1. **It would discard the 1d work.** The frame, the HKDF key schedule, the
   `SessionStore`, the anti-replay window and their tests are all built around a
   handshake that yields `(session_id, role, send_key, receive_key)`. TLS gives
   a byte stream with no such model; wiring it in means deleting or bypassing
   most of 1d.
2. **It needs an X.509 identity layer.** The project's identity is an Ed25519
   keypair and a `device_id`, pinned in a JSON trust store. TLS wants
   certificates, chain validation, rotation and pinning — a second identity
   system to build, test and document.
3. **It removes the educational value.** SecureSync exists to demonstrate
   protocol design end to end. Delegating the handshake to `ssl` would make the
   replay-protection and session work pointless as a portfolio piece.
4. **It still needs careful configuration** (verification modes, SNI, ALPN,
   hostname checks) and would not give the `session_id`/role model the 1d frame
   depends on.

The honest conclusion: **TLS 1.3 would be the right engineering choice for a
product; Option B is the right choice for this project**, and the handshake is
therefore a **custom, unaudited protocol** (§10). This section will become an
ADR (see §12).

---

## 9. Composition with 1d

Both the handshake and the 1d layer meet at one contract:

```text
HandshakeResult(session_id, role, send_key, receive_key,
                peer_transfer_port, peer_manifest_port)
```

`SecureChannel.seal/open`, `SessionStore.put/get_by_session_id`, the
`[version|direction|packet_type|session_id|nonce|ciphertext|tag]` frame and
`AntiReplayWindow` are untouched. Only `CURRENT_VERSION` moves 2 → 3, and
`UnsupportedVersionError` keeps a v2 peer from being misparsed.

---

## 10. Security properties and limitations

| Property | v3 SIGMA-style |
|---|---|
| Mutual authentication | Yes (`sig_r`, `sig_i`) |
| Freshness | Yes (fresh `e_i, e_r, n_i, n_r`; `sig_r` binds message 1) |
| Transcript binding | Yes (`t2`, `t2s`, `t3s`; ids and ports included) |
| Key confirmation | **Explicit** (`mac_r`, `mac_i`) |
| Identity hiding | **No** — `id_i`/`id_pub_i` are cleartext in message 1. Documented limitation; can be added later by encrypting them under a key derived from `ss`. |
| Forward secrecy | Yes (ephemeral ECDH; static keys only sign) |
| Replay | Replayed message 1 ⇒ responder answers with fresh `e_r/n_r`, attacker cannot produce `sig_i`/`mac_i`; a full replay fails the transcript hash |
| Reflection | Direction-specific type bytes and separate `k_r`/`k_i` |
| Malleability | Any byte flip breaks a signature or MAC |
| Downgrade | Version byte checked first and bound into the transcript |
| Audit status | **Custom, unaudited protocol** (primitives are audited; the composition is not) |

The identity-hiding limitation is accepted for LAN peer-to-peer sync. It must
be stated in `README.md` and `docs/security.md`, not only here.

---

## 11. Implementation plan (small green commits)

Each commit passes the full gate (pytest, ruff, black --check, mypy --strict)
and is pushed before the next begins.

1. **`feat(handshake): add v3 message encoding and known-answer tests`**
   Pure encode/decode for `m1`/`m2`/`m3`, the version byte and the transcript
   hashes, with fixed keys/nonces and frozen expected bytes. No wiring.
2. **`feat(handshake): add the v3 key schedule`**
   `master`/`k_r`/`k_i`/`session_id`/`i2r`/`r2i` and the SAS derivation, plus
   tests (including a reflection test for `k_r` vs `k_i`).
3. **`feat(handshake): add the initiator state machine`**
   `initiate()` over the three flights, timeouts, `UnsupportedVersionError`,
   TOFU checks, `mac_r` verification.
4. **`feat(handshake): add the responder state machine`**
   `accept()` over the three flights, half-open cap, timeout, `sig_i`/`mac_i`
   verification, no session stored before confirmation.
5. **`feat(protocol)!: wire the v3 handshake and bump CURRENT_VERSION to 3`**
   `HandshakeResult`, `main.py`, the session coordinator, `HandshakeServer`,
   integration tests, and a v2 peer rejected with `UnsupportedVersionError`.
6. **`test(security): retire the hello-malleability xfails`**
   Remove the two strict `xfail` markers and assert rejection; add replay,
   MITM, key-confirmation and downgrade tests.
7. **`docs: document the v3 handshake and the custom-protocol caveat`**
   `docs/protocol.md`, `docs/security.md`, `README.md`, and the ADRs in §12.

---

## 12. ADRs, documentation and sign-off

- **ADR-0028 — security-audit summary.** Reserved; 0027 is taken. Written when
  the audit is done.
- **TLS rationale (§8)** becomes an ADR after 1e (0029 or later), or is folded
  into ADR-0028.
- **README / `docs/security.md`** must state: *the handshake is a custom,
  unaudited protocol (SIGMA-style, not TLS or Noise); the primitives are
  audited, the composition is not.*

**Sign-off needed before any code:** confirm this amended design, then
implementation proceeds in the seven commits above.
