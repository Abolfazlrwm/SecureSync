# Architecture Decision Records

Numbered sequentially, never renumbered or deleted (a superseded decision
gets a new ADR that says so and links back, rather than editing history).

| # | Title | Status |
|---|---|---|
| [0001](0001-clean-architecture-with-ports-and-adapters.md) | Clean Architecture with Ports and Adapters | Accepted |
| [0002](0002-asyncio-as-the-async-runtime.md) | `asyncio` as the Async Runtime | Accepted |
| [0003](0003-cryptography-pyca-as-the-crypto-library.md) | `cryptography` (pyca) as the Sole Cryptographic Library | Accepted |
| [0004](0004-binary-header-with-msgpack-payload.md) | Fixed Binary Header + MessagePack Payload | Accepted |
| [0005](0005-sqlite-for-metadata-storage.md) | SQLite for Metadata Storage | Accepted |

## Template for new ADRs

```markdown
# ADR NNNN: <Title>

**Status:** Proposed | Accepted | Superseded by ADR-XXXX
**Date:** <phase or date>

## Context
<What forces are at play; what problem needs a decision>

## Decision
<The decision, stated plainly>

## Consequences
<Positive and negative trade-offs accepted>

## Rejected: <alternative>
<Why it wasn't chosen>
```
