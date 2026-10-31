# 1e — Handshake redesign: transcript binding, freshness and key confirmation

Status: **design only, no code**. This document compares two options and
recommends one. Nothing here is implemented; the current wire protocol is still
v2 (the 1d replay-protected frame) with the single-message hello/reply handshake
described in §2.

Related documents:

- [`docs/design/1d-replay-protection.md`](1d-replay-protection.md) — the frame,
  key schedule and session model this design has to compose with.
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

Item 1e replaces the handshake. It must deliver, by design rather than by
accident:

1. **Freshness from both sides.** Every handshake must mix fresh randomness
   contributed by *both* peers into the key schedule, so a captured handshake
   can never be replayed to reproduce a session.
2. **Transcript binding.** Every identity field, ephemeral key, nonce and
   advertised port that the session depends on must be covered by an
   authenticated value (a signature or a MAC), so none of them can be
   relabelled in flight.
3. **Mutual authentication** against the long-term identity (Ed25519 today).
4. **Explicit key confirmation**, so neither side starts sending file data
   before the other has proven it derived the same keys.
5. **Forward secrecy** — compromise of long-term identity keys must not expose
   past session keys.
6. **Composition with 1d** — the output must still be
   `(session_id, role, send_key, receive_key)` so `SecureChannel`,
   `SessionStore`, the frame and the anti-replay window are unchanged.

Explicitly **out of scope** for 1e: pairing UX and the `pair/trust/untrust`
commands (that is 1f, discussed in §8), additional security tests beyond the
handshake (1g), and the ADR-0027/threat-model-to-test mapping (1h).

---

## 2. What exists today (v2), precisely

The current handshake is a **single msgpack message each way**, length-prefixed
with a 4-byte big-endian prefix (`read_length_prefixed`, bounded by
`MAX_HANDSHAKE_MESSAGE_SIZE`). It lives in
`src/securesync/infrastructure/networking/x25519_handshake.py`.

### 2.1 Hello (initiator → responder)

| Field | Size | Notes |
|---|---|---|
| `device_id` | variable (msgpack) | config string or `uuid4()`, **independent of the identity key** (`main.py:117`) |
| `transfer_port` | int | advertised chunk-transfer port |
| `manifest_port` | int | advertised manifest-exchange port |
| `salt` | 16 bytes | fresh, from the initiator |
| `public_key` | 32 bytes | initiator X25519 ephemeral |
| `identity_public_key` | 32 bytes | initiator Ed25519 long-term public key |
| `signature` | 64 bytes | `Ed25519(salt ‖ public_key)` |

### 2.2 Reply (responder → initiator)

Same shape, with a **fresh** responder X25519 ephemeral generated per
connection, and `signature = Ed25519(request_salt ‖ responder_public_key)`.

### 2.3 Key schedule (v2)

```text
master     = HKDF(ECDH(e_i, e_r), salt,
                  lp("securesync-master-v2") ‖ lp(e_i) ‖ lp(e_r))
session_id = HKDF(ECDH(e_i, e_r), salt,
                  lp("securesync-session-id") ‖ lp(e_i) ‖ lp(e_r))[:8]
i2r_key    = HKDF(master, "",
                  lp("securesync-initiator-to-responder") ‖ lp(id_i) ‖ lp(id_r)
                  ‖ session_id ‖ lp(e_i) ‖ lp(e_r))
r2i_key    = HKDF(master, "",
                  lp("securesync-responder-to-initiator") ‖ … same common …)
```

`lp(x)` is a 2-byte big-endian length followed by `x`
(`session_keys.length_prefixed`).

### 2.4 What the current signatures actually cover

- `sig_i` covers `salt ‖ e_i`.
- `sig_r` covers `salt ‖ e_r`.

Neither signature covers the other side's identity or ephemeral, and **neither
covers `device_id` or the advertised ports**. That is the whole of ADR-0027:

| Property | Current v2 | Consequence |
|---|---|---|
| Freshness | responder ephemeral only, **unsigned by the initiator** | a replayed hello gets a new `session_id` only because the responder happens to draw a fresh ephemeral; the protection is incidental |
| Transcript binding | none | `device_id`, `transfer_port`, `manifest_port` are malleable (two strict-`xfail` tests) |
| Key confirmation | none | no proof the peer derived the same keys before data flows |
| Identity hiding | none | both identities travel in cleartext |

The replay test file proves the practical impact: a replayed hello does **not**
reproduce a session today (fresh responder ephemeral ⇒ different shared secret ⇒
different `session_id` ⇒ the captured frame names a vanished session and is
dropped with `UnknownSessionError`), but if a session id were ever reproducible
a captured frame would be accepted with a fresh window and counters reset, with
only the timestamp skew in the way. 1e must make that impossible by design.

---

## 3. Option A — Noise XX (`Noise_XX_25519_ChaChaPoly_SHA256`)

### 3.1 Pattern

Noise XX has no pre-messages and three flights:

```text
XX:
  -> e
  <- e, ee, s, es
  -> s, se
```

1. **Initiator → Responder:** ephemeral public key `e`.
2. **Responder → Initiator:** ephemeral `e`, `ee` DH, encrypted static `s`,
   `es` DH.
3. **Initiator → Responder:** encrypted static `s`, `se` DH.

After flight 3 both sides have authenticated the other's static key and share a
`CipherState` pair from `Split()`.

### 3.2 Python library landscape (checked 2026-10-31)

| Package | Version | Last release | `requires_python` | Health | Verdict |
|---|---|---|---|---|---|
| `noiseprotocol` | 0.3.1 | **2020-03-03** | `~=3.5` | MIT, 222★, 7 open issues, repo last pushed 2023-05-09, CI historically Linux-only | Mature but **unmaintained** for 6.5 years; untested on Windows (our CI matrix includes Windows) and on 3.12/3.13 |
| `noiseframework` | 1.3.0 | 2025-11-25 | `>=3.8` | MIT, **0★**, created 2025-11-16, 1 open issue, single author, 0.1.0→1.3.0 in 9 days | Supports `Noise_XX_25519_ChaChaPoly_SHA256`, but **unvetted** — unacceptable as a security-critical dependency |
| `noise-py` | 0.0.4 | 2015-10-13 | — | client for an unrelated `eleme/noise` project | Not the Noise Protocol |
| `pynoise` | 3.0.0 | 2025-08-06 | — | libnoise (terrain/Perlin maps) | Not the Noise Protocol |
| `noise` | 1.2.2 | — | — | Perlin noise | Not the Noise Protocol |
| `snow` | 0.3.1 | 2020-06-05 | — | ServiceNow asyncio client | Not the Noise Protocol |

There is **no maintained, widely-vetted Python Noise implementation**. The
choice is therefore between a stale-but-mature library and a brand-new
single-author one — or implementing the state machine ourselves.

### 3.3 Identity model change

Noise authenticates with **static X25519 keys** (`s` is a DH public key), not
Ed25519 signatures. SecureSync's identity is an Ed25519 keypair
(`Ed25519IdentityProvider`), and the trust store pins
`device_id → Ed25519 public key`. Adopting Noise forces one of:

- **A1 — replace Ed25519 with static X25519.** `device_id` would be derived
  from the static public key (e.g. `base32(SHA256(pk))[:16]`) instead of being a
  free config string / `uuid4`. The trust store re-pins every peer under the new
  key type, and `securesync init` changes.
- **A2 — dual keys.** Keep Ed25519 for compatibility and add a static X25519 for
  Noise. Two long-term keys, two trust anchors, more to get wrong.
- **A3 — Ed25519 inside Noise.** Not possible: the `s` token is a DH public key,
  and the signature-based Noise variants are non-standard extensions.

All three are a breaking change to the identity model, the trust store and the
`init` UX.

### 3.4 Composition with 1d

Good news: the composition is clean. Noise `Split()` yields two 32-byte
transport keys, one per direction. Map them directly:

```text
i2r_key, r2i_key = Split(ck)              # Noise transport keys
session_id       = SHA256(final_h)[:8]    # or HKDF(ck, "securesync-1e-sid")[:8]
role             = initiator | responder
```

`SecureChannel`, `SessionStore`, the v2 frame
(`version|direction|packet_type|session_id|nonce|ciphertext|tag`) and
`AntiReplayWindow` all keep working unchanged — they only consume
`(session_id, role, send_key, receive_key)`.

### 3.5 Security properties

| Property | Noise XX |
|---|---|
| Mutual authentication | Yes (static DH) |
| Freshness | Yes (both ephemerals mixed into `ck`/`h`) |
| Transcript binding | Yes (handshake hash `h`) |
| Key confirmation | **Implicit** (first transport message); an explicit MAC must be added |
| Identity hiding | Yes against passive observers; no against active attackers |
| Forward secrecy | Yes (`ee`) |
| Replay | Prevented (fresh ephemerals + `h`) |
| Malleability | Prevented (everything is inside the encrypted/authenticated transcript) |

### 3.6 What we must implement

- **With `noiseprotocol`:** the 3-flight wiring, mapping `Split()` to the 1d
  keys, an explicit key-confirmation MAC, and a `session_id` derivation. No
  crypto, but we inherit an unmaintained dependency and an identity migration.
- **DIY:** the full Noise state machine — `InitializeSymmetric`, `MixHash`,
  `MixKey`, `EncryptAndHash`, `DecryptAndHash`, `Split`, plus XX message
  handling — validated against the official Noise test vectors. This is several
  hundred lines of subtle, security-critical code.

### 3.7 Migration cost

**High.** Identity model (Ed25519 → static X25519), trust-store migration,
`init` UX, `HandshakeResult`, every handshake test, the `paired_sessions()`
helper, and a protocol bump to v3. Plus a dependency decision with no good
answer (§3.2).

### 3.8 Test plan

- Official Noise XX test vectors (handshake hash and transport keys).
- Interop against `noiseprotocol` if we implement the state machine ourselves.
- Replay: replayed flight 1 yields no session; a full replayed handshake is
  rejected because the responder draws fresh ephemerals.
- Malleability: flipping any byte in any flight fails authentication;
  relabelled identity/ports fail.
- Key confirmation: MAC mismatch ⇒ reject.
- Forward secrecy: static-key compromise does not yield past session keys.

---

## 4. Option B — SIGMA-style handshake on `cryptography` only

A simplified SIGMA (the construction IKEv2 is based on), built from primitives
the project already uses: X25519 ECDH, Ed25519 signatures, HKDF-SHA256,
HMAC-SHA256, and `length_prefixed`.

### 4.1 Design

Three messages. `H = SHA256`, `lp(x)` = 2-byte BE length ‖ `x`, and
`T1 = b"securesync-1e-handshake-v1"` is a domain-separation prefix on every
hash and signature.

**Message 1 (initiator → responder)**

```text
type      : 1 byte   0x01
e_i       : 32       initiator X25519 ephemeral public key
n_i       : 32       initiator random nonce
id_i_len  : 2        big-endian
id_i      : variable initiator device_id (UTF-8)
sig_i     : 64       Ed25519
```

```text
sig_i = Ed25519_sign(sk_i, H(T1 ‖ 0x01 ‖ lp(e_i) ‖ lp(n_i) ‖ lp(id_i)))
```

**Message 2 (responder → initiator)**

```text
type      : 1 byte   0x02
e_r       : 32       responder X25519 ephemeral public key (fresh)
n_r       : 32       responder random nonce (fresh)
id_r_len  : 2
id_r      : variable responder device_id
sig_r     : 64       Ed25519
mac_r     : 32       HMAC-SHA256 key confirmation
```

```text
t2    = H(T1 ‖ 0x02 ‖ lp(e_i) ‖ lp(n_i) ‖ lp(id_i)
                 ‖ lp(e_r) ‖ lp(n_r) ‖ lp(id_r))
sig_r = Ed25519_sign(sk_r, t2)
t2s   = H(t2 ‖ lp(sig_r))
ss    = X25519(e_i_priv, e_r)          # responder computes with e_r_priv
master = HKDF(ss, salt = lp(n_i) ‖ lp(n_r),
              info = lp("securesync-1e-master") ‖ lp(e_i) ‖ lp(e_r)
                     ‖ lp(id_i) ‖ lp(id_r))
k_r    = HKDF(master, lp("securesync-1e-kr"))
mac_r  = HMAC-SHA256(k_r, t2s)
```

**Message 3 (initiator → responder)**

```text
type      : 1 byte   0x03
mac_i     : 32       HMAC-SHA256 key confirmation
```

```text
k_i    = HKDF(master, lp("securesync-1e-ki"))
t3     = H(t2s ‖ lp(mac_r))
mac_i  = HMAC-SHA256(k_i, t3)
```

**Transport keys** (identical derivation on both sides):

```text
session_id = HKDF(master, lp("securesync-1e-sid"), length = 8)
common     = lp(id_i) ‖ lp(id_r) ‖ session_id ‖ lp(e_i) ‖ lp(e_r)
i2r_key    = HKDF(master, lp("securesync-1e-i2r") ‖ common)
r2i_key    = HKDF(master, lp("securesync-1e-r2i") ‖ common)
```

### 4.2 What is signed / MACed

| Value | Covers |
|---|---|
| `sig_i` | `T1`, message type, `e_i`, `n_i`, `id_i` |
| `sig_r` | `T1`, message type, **the entire message 1**, `e_r`, `n_r`, `id_r` |
| `mac_r` | `t2s` = the message-2 transcript **including `sig_r`** |
| `mac_i` | `t3` = the full transcript **including `mac_r`** |
| transport keys | `master` ⇒ `ss`, both nonces, both ephemerals, both ids |

The responder's signature binds the initiator's contribution, and the
initiator's confirmation MAC binds the responder's signature. Nothing that the
session depends on is left outside an authenticated value — including
`device_id` and the advertised ports (which move into the signed transcript).

### 4.3 Explicit rekey

Add `PACKET_REKEY = 0x04` to `PacketType` (the value is free between `AUTH =
0x03` and `FILE_MANIFEST = 0x10`). A `REKEY` frame is the last frame encrypted
under the old key; both sides then compute:

```text
master'    = HKDF(master, lp("securesync-1e-rekey") ‖ lp(rekey_counter))
session_id'= HKDF(master', lp("securesync-1e-sid"), length = 8)
i2r', r2i' = … same directional derivation from master' and session_id' …
```

`rekey_counter` starts at 1 and increments per rekey; a `REKEY` frame received
out of order or with a stale counter is rejected. The simpler fallback — and
what 1d already assumes — is to open a **new handshake** on counter exhaustion;
1e can ship re-running the handshake first and add `REKEY` later.

### 4.4 Security properties

| Property | SIGMA-style |
|---|---|
| Mutual authentication | Yes (`sig_i`, `sig_r`) |
| Freshness | Yes (fresh `e_i, e_r, n_i, n_r`; `sig_r` binds message 1) |
| Transcript binding | Yes (explicit transcript hash; ids and ports inside it) |
| Key confirmation | **Explicit** (`mac_r`, `mac_i`) |
| Identity hiding | **No** (ids are cleartext; can be added by encrypting them under a key derived from `ss`) |
| Forward secrecy | Yes (ephemeral ECDH; static keys only sign) |
| Replay | Replayed message 1 ⇒ responder answers with fresh `e_r/n_r`, attacker cannot produce `mac_i`; a full replay fails the transcript hash |
| Reflection | Direction-specific type bytes and separate `k_r`/`k_i` keys |
| Malleability | Any byte flip breaks a signature or MAC |

### 4.5 What we must implement

The three-message state machine (~250–400 lines) on top of `cryptography`. No
new dependency. We reuse from 1d: `length_prefixed`, the HKDF helpers, the
`SessionKeys`/`HandshakeResult` shapes, the frame, the anti-replay window and
the session store.

### 4.6 Migration cost

**Medium.** Keep Ed25519 identity, `device_id`, and the trust store as they are.
Replace `initiate`/`accept` with the 3-flight flow, extend the key schedule with
nonces and the transcript hash, bump `CURRENT_VERSION` to 3, and update the
handshake tests and `paired_sessions()`. No identity migration, no `init`
change.

### 4.7 Test plan

1. Happy path: both sides derive the same `session_id`, `i2r`, `r2i`.
2. Replay message 1: no session; replay all three: rejected (fresh `e_r/n_r`).
3. Malleability: flip each field ⇒ signature/MAC failure; relabel `device_id`
   or ports ⇒ failure (this retires the two strict-`xfail` tests).
4. MITM: substituted ephemeral ⇒ signature failure.
5. Key confirmation: wrong `mac_r`/`mac_i` ⇒ reject.
6. Forward secrecy: static-key compromise does not yield session keys.
7. Reflection: message 2 fed to an initiator is rejected on type/prefix.
8. Known-answer test with fixed keys and nonces.

---

## 5. Side-by-side comparison

| Criterion | A — Noise XX | B — SIGMA-style |
|---|---|---|
| Mutual authentication | Yes | Yes |
| Freshness | Yes | Yes |
| Transcript binding | Yes (`h`) | Yes (explicit) |
| Key confirmation | Implicit (add MAC) | Explicit |
| Identity hiding | Passive: yes; active: no | No (optional) |
| Forward secrecy | Yes | Yes |
| Identity model | Static X25519 (**change**) | Ed25519 (**unchanged**) |
| Trust store | Re-pin (migration) | Unchanged |
| New dependency | `noiseprotocol` (stale) or `noiseframework` (unvetted) or DIY | None |
| Code we write | Wire + mapping, or full state machine | 3-flight state machine |
| Migration cost | **High** | **Medium** |
| Composes with 1d | Yes | Yes |
| Auditability | Depends on library | Fully ours, small |

---

## 6. Recommendation: Option B (SIGMA-style)

1. **No acceptable Noise library exists in Python.** `noiseprotocol` has not
   shipped since March 2020 and targets Python 3.5 with historically Linux-only
   CI; `noiseframework` is a 0-star, single-author package created in November
   2025. For a project that claims honesty over marketing, neither is a
   defensible security-critical dependency.
2. **It preserves the identity model.** Ed25519, `device_id` and the trust store
   stay as they are; there is no peer re-pinning and no `init` change.
3. **It reuses 1d.** The HKDF helpers, `length_prefixed`, `SessionKeys`, the
   frame and the anti-replay window are already built and tested.
4. **Explicit key confirmation** is a first-class part of the design rather than
   something bolted onto Noise.
5. **It is auditable.** ~300 lines we can read, test and explain, versus
   trusting an unmaintained or unvetted state machine.

The honest trade-off: we are implementing a security protocol ourselves. That is
acceptable here because it is a small, well-understood three-message
construction, it is tested hard (replay, malleability, MITM, confirmation,
forward secrecy), and the alternative libraries are worse. The main cost is
code we must get right, not a dependency we cannot audit.

Known limitation to state in the docs: **no identity hiding** against passive
observers. Acceptable for LAN peer-to-peer sync; can be added later by
encrypting `id_i`/`id_r` under a key derived from `ss`.

---

## 7. Composition with 1d (both options)

Both options emit the same contract, so nothing downstream changes:

```text
HandshakeResult(session_id, role, send_key, receive_key,
                peer_transfer_port, peer_manifest_port)
```

`SecureChannel.seal/open`, `SessionStore.put/get_by_session_id`, the
`[version|direction|packet_type|session_id|nonce|ciphertext|tag]` frame and
`AntiReplayWindow` are untouched. Only `CURRENT_VERSION` moves 2 → 3, and
`UnsupportedVersionError` keeps a v2 peer from being misparsed.

---

## 8. How 1f (explicit pairing) plugs into each option

1f adds a short fingerprint / SAS, `securesync pair`, a real `trust`, and
`untrust` that also purges sessions. Note the current CLI is already confusing:
`securesync trust <device>` **deletes** the pin ("reset trust") — 1f should
split that into `trust` (confirm/pin) and `untrust` (forget + purge).

### 8.1 With Option A (Noise XX)

- The static X25519 keys are the pairing anchor. After the handshake both sides
  know each other's static key, and Noise's handshake hash `h` binds them.
- `SAS = H(h)` rendered as 6 digits or 4 words; users compare out-of-band.
- `pair` = run the handshake, show the SAS, wait for confirmation, then pin the
  static key. `untrust` deletes the pin and purges all sessions for that peer
  (the 1d `SessionStore.remove_by_peer` already exists).

### 8.2 With Option B (SIGMA-style)

- `SAS = H(t3 ‖ lp(mac_i))`, i.e. the final transcript, which already includes
  both Ed25519 identities, both ephemerals, both nonces, both signatures and
  both confirmation MACs.
- `pair` = run the 3-flight handshake, show the SAS, confirm, then pin the
  Ed25519 key (the existing TOFU anchor). `untrust` deletes the pin and purges
  sessions via `remove_by_peer`.
- Because the SAS is derived from the same transcript the signatures cover, a
  matching SAS proves no MITM — and the trust store type does not change.

Either way, 1f is a thin layer over the 1e handshake: expose the final
transcript hash, add two CLI commands, and call the existing session purge.

---

## 9. Decision needed

Choose **A (Noise XX)** or **B (SIGMA-style)**. If B, confirm:

1. Identity hiding stays out of scope for 1e (cleartext ids), or is added now.
2. Rekey ships as re-running the handshake first, with `REKEY` (0x04) as a
   follow-up.

No implementation starts until this choice is made.
