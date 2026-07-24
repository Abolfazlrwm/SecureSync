# ADR 0002: `asyncio` as the Async Runtime

**Status:** Accepted
**Date:** Phase 0

## Context

SecureSync needs to handle concurrent filesystem events, multiple peer
connections, and streamed file transfers without blocking. The main
candidates in the Python ecosystem are the standard library's `asyncio`,
or third-party alternatives such as `trio`/`anyio`.

## Decision

Use `asyncio` from the standard library as the sole async runtime.

## Consequences

**Positive**
- No additional dependency for the concurrency model itself.
- Every async-capable library in the chosen stack (and the vast majority of
  the wider Python networking ecosystem) targets `asyncio` natively.
- Contributors are more likely to already know `asyncio` than `trio`,
  lowering the contribution barrier for an open-source project.

**Negative / trade-offs accepted**
- `trio`'s structured concurrency model is arguably safer by construction
  (no orphaned tasks) — SecureSync mitigates this with disciplined use of
  `asyncio.TaskGroup` (3.11+) instead of manually managed
  `create_task` calls, capturing most of the same safety benefit.

## Rejected: `trio` / `anyio`

Rejected as the primary runtime because it would add a second async
ecosystem to support (or require `anyio` as a compatibility shim) for a
project whose dependencies (`watchdog`, planned TLS handling) already
assume or integrate most naturally with `asyncio`.
