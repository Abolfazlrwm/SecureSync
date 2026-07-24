# ADR 0004: Fixed Binary Header + MessagePack Payload

**Status:** Accepted
**Date:** Phase 0

## Context

SecureSync needs a wire protocol that (a) lets a receiver validate and
route a packet before parsing a potentially large payload, and (b) can
evolve (new fields, new packet types) without breaking older peers.
Candidates: a fully custom binary format end-to-end, JSON over a
length-prefixed frame, Protocol Buffers, or a hybrid (fixed binary header +
schema-flexible payload encoding).

## Decision

Use a fixed 32-byte binary header (hand-packed, documented in
`docs/protocol.md`) followed by a MessagePack-encoded payload.

## Consequences

**Positive**
- The header alone is enough to validate (`magic`, `version`, `crc32`) and
  route (`packet_type`) a packet without touching the payload — important
  for rejecting malformed/malicious traffic cheaply (see the DoS row in
  `docs/security.md`).
- MessagePack payloads are maps: new optional fields can be added by a
  newer sender without bumping the protocol version, since older receivers
  simply ignore unknown keys.
- MessagePack is compact and has implementations in essentially every
  language, keeping the door open to a future non-Python client.

**Negative / trade-offs accepted**
- A fully custom end-to-end binary format (à la Protocol Buffers with
  generated code) could be marginally more compact and faster to
  (de)serialize — rejected because Protocol Buffers' schema/codegen
  workflow is heavier than this project's needs justify, and hand-packing
  every payload field would reintroduce the versioning fragility
  MessagePack's map-based payloads avoid.
- JSON-over-length-prefix was rejected primarily on size/performance
  grounds for a protocol that streams potentially very large chunk data
  alongside metadata.

## Rejected: pure JSON protocol

Rejected — JSON's text encoding overhead is unattractive for a protocol
that needs to move large volumes of chunk data efficiently, and JSON has no
native compact representation for the fixed-size header fields (magic
number, CRC, timestamp) that benefit from being parsed as raw bytes.
