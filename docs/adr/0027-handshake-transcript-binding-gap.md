# ADR 0027: The Handshake Is Not Transcript-Bound — a Disclosed Gap for Item 1e

**Status:** Accepted (discloses a known gap; closed by the 1e handshake)
**Date:** Phase 22

## Context

ADR-0018 introduced a one-shot X25519 handshake: the initiator sends a
`salt`, an ephemeral public key and an Ed25519 signature over
`salt ‖ ephemeral_pub`; the responder answers with its own ephemeral and a
signature over `salt ‖ responder_ephemeral`. ADR-0019 wrapped that in
trust-on-first-use. ADR-0020 added session keys, and the 1d work
(`docs/design/1d-replay-protection.md`) replaced the message counter with a
per-session sliding replay window keyed by `session_id`.

1d deferred three items to 1e: a transcript-bound handshake, an explicit
key-confirmation message, and an explicit rekey/teardown signal. That
deferral was recorded as a to-do, not as a measured risk.

While implementing 1d it was claimed that **a replayed hello re-derives the
same `session_id`**. If true, that would be a serious break: a captured
session could be resurrected with a fresh replay window and counters reset to
1, making captured frames acceptable again.

`tests/security/test_handshake_replay.py` was written to settle the question
with real sockets and real crypto rather than by reading the code.

## Decision

### The claim was wrong, and we say so

The probe captures a hello, replays it byte-for-byte after dropping the
responder's session state, and compares the two results. The `session_id`
**differs**, because the responder calls `generate_key_pair()` inside
`accept()` for every connection: a replayed hello is answered with a fresh
ephemeral, so the ECDH shared secret — and therefore the whole key schedule —
is new. The captured frame then names a `session_id` that no longer exists and
is rejected with `UnknownSessionError` before decryption.

So there is **no key-recovery or frame-replay break today**. The correction is
recorded in `docs/design/1d-replay-protection.md` §10.1 rather than quietly
dropped.

### But the property is incidental, and two gaps are real

The protection above is a side effect of where `generate_key_pair()` happens
to be called, not an enforced property. We therefore disclose:

1. **No freshness check on the hello.** The responder cannot tell a fresh
   hello from an old one. Replayed hellos are cheap state-churn: they consume
   per-peer and per-IP budget and create sessions the responder will never use.
   The per-source-IP handshake rate limit and the `MAX_UNCONFIRMED_PER_PEER`
   cap bound the damage, but neither is a freshness proof.
2. **No transcript binding.** The signature covers `salt ‖ ephemeral_pub`
   only. `device_id`, `transfer_port` and `manifest_port` travel unsigned, so a
   captured hello can be relabelled: the responder will pin the *real* peer's
   identity key under an attacker-chosen `device_id`, and will store
   attacker-chosen transfer/manifest ports for that peer. The identity key
   itself is implicitly bound (the signature verifies against the transmitted
   key, so swapping it fails), but nothing else is.
3. **No key confirmation.** The responder commits a session it never learns is
   usable. A confirmation MAC is also the cheapest way to make the freshness
   property explicit instead of accidental.

The severity is bounded — the relabelled session is one only the true
initiator can speak on, so this is trust-store pollution and port redirection,
not impersonation of the peer — but "bounded" is not "absent", and the whole
class of bug disappears the moment the transcript is signed.

### What we do about it now

* `test_relabelled_device_id_is_rejected` and
  `test_relabelled_ports_are_rejected` are committed as **strict** `xfail`
  with the 1e reason attached. Strict means that when 1e closes the gap they
  become *unexpected passes* and the build fails until the markers are
  removed — the fix cannot land silently.
* `test_restored_state_accepts_a_captured_frame_until_the_timestamp_ages_out`
  documents the consequence of the incidental property: with a reproducible
  `session_id`, a captured frame is accepted and only the timestamp skew
  stops it. This is the regression trap for any future change to the key
  schedule.
* The gap is listed in `docs/security.md` §3.2 and in the 1d design doc §10.

## Consequences

**Positive**

* The threat model no longer overstates the handshake. "Bound to long-term
  identity keys" is true; "binds the whole handshake" was not.
* Two real weaknesses are now executable tests with an expiry condition,
  instead of prose in a deferred-items list.
* The correction of a wrong internal claim is in the repo, so the next person
  to read the 1d notes does not inherit the error.

**Negative**

* A captured hello can still be relabelled and can still burn session slots
  until 1e lands.
* `strict=True` xfails are a deliberate build-time liability: they will fail
  the suite on the day 1e is implemented, which is the point but does mean 1e
  cannot merge without touching this file.

## Rejected: leave the deferral as prose

The original plan was to note "transcript-bound handshake: deferred to 1e" in
the design doc and move on. Rejected because the deferral note gave no way to
tell whether the gap was theoretical or exploitable, and the claim that had
been made about replay was wrong — which is exactly the situation a written
test resolves and a written sentence does not.

## Rejected: fix the transcript binding inside 1d

Adding a transcript hash to the current one-shot handshake would have meant a
third wire format revision in as many commits, and the 1e redesign replaces
the handshake wholesale (see `docs/design/1e-handshake.md`). Patching the
format that is about to be deleted is churn, not progress.
