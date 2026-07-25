# ADR 0006: Filesystem Watcher Port with a `watchdog` Adapter

**Status:** Accepted
**Date:** Phase 1

## Context

Phase 1 requires real-time filesystem monitoring (create/modify/delete/
move/rename) across multiple directories, optionally recursively, with
duplicate-event suppression, async dispatch to multiple consumers, and
graceful shutdown. `docs/architecture.md` already named `watchdog` as the
planned library (ADR 0001 established the ports/adapters boundary in
general terms); this ADR records the concrete decisions specific to this
module: where the port boundary sits, how debouncing is handled without
leaking a technical concern into the domain, and how a background-thread
library is bridged into `asyncio`.

Two alternatives were considered for detecting filesystem changes:

1. Hand-rolled polling (periodically `stat()` every file under each
   watched directory and diff against the previous snapshot).
2. `watchdog`, a mature, cross-platform library that wraps OS-native
   notification APIs (`inotify` on Linux, `FSEvents` on macOS,
   `ReadDirectoryChangesW` on Windows).

## Decision

- `domain/watcher.py` defines `FileWatcher` (an `ABC`) as the port, and
  `FileSystemEventObserver` (a `runtime_checkable Protocol`) as the
  Observer-pattern participant. Neither imports `watchdog` or performs
  any I/O — `domain/` still has zero outgoing imports, per ADR 0001.
- `infrastructure/filesystem/watchdog_watcher.py` provides
  `WatchdogFileWatcher(FileWatcher)`, the only module in the codebase
  that imports `watchdog`. It owns the `watchdog` background thread,
  translates raw events into domain `FileSystemEvent` objects, and
  bridges thread → event loop via `asyncio.run_coroutine_threadsafe`
  (the loop is captured with `asyncio.get_running_loop()` at `start()`
  time, since `watchdog` calls handler callbacks from its own OS thread,
  not from the asyncio loop).
- Debouncing is treated as an **infrastructure** concern, not a domain
  rule: `EventDebouncer` (`infrastructure/filesystem/debounce.py`)
  suppresses repeat notifications for the same logical change within a
  configurable time window. It exists because `watchdog`/the underlying
  OS API can emit several raw notifications for what is logically one
  change (observed in practice: a single buffered write can produce
  `created` + multiple `modified` events); it is not a rule about *when
  a sync should happen*, which is what would make it a domain concern.
- `watchdog` was chosen over hand-rolled polling: polling either wastes
  CPU (short intervals) or has poor change-detection latency (long
  intervals), and reimplementing `inotify`/`FSEvents`/
  `ReadDirectoryChangesW` bindings by hand would fight the OS for a
  well-solved problem. `watchdog` is mature, actively maintained, and
  already listed as the intended dependency in `docs/architecture.md`.
- `application/use_cases/monitor_directories.py` provides
  `MonitorDirectoriesUseCase`, which owns the watcher's start/stop
  lifecycle (as an `async with`-compatible context manager for
  guaranteed graceful shutdown) and observer registration. It depends
  only on the `FileWatcher` port — never on `WatchdogFileWatcher`
  directly — so the concrete adapter is supplied via dependency
  injection at the composition root (today: test fixtures and
  integration tests; from Phase 9 onward: the CLI entry point).

## Consequences

**Positive**
- `domain/` and `application/` are fully unit-testable with an in-memory
  `FakeFileWatcher` test double — no real filesystem, thread, or event
  loop needed for that layer's tests (see `tests/doubles.py`).
- Swapping `watchdog` for a different notification mechanism later
  (e.g. a lower-level `inotify` binding for a performance-critical path)
  requires writing one new `FileWatcher` adapter; no change to
  `domain/` or `application/`.
- Debounce tuning (or disabling it entirely, via `debounce_seconds=0`)
  is a constructor parameter on the adapter — an infrastructure
  concern, changeable without touching the port contract.
- The Observer pattern is directly usable today (any
  `FileSystemEventObserver` can `subscribe`); it does not require the
  `core/` event bus (not yet built) to exist first, while still leaving
  room for consumers to be re-wired through that bus later, once
  multiple independent subsystems (chunk engine, indexer) need the same
  event stream, without changing the `FileWatcher` port itself.

**Negative / trade-offs accepted**
- `watchdog` runs its own background OS thread per platform backend,
  which means every event crosses a thread boundary before reaching
  `asyncio` consumers. This is more moving parts than a purely
  single-threaded async implementation, but avoids blocking the event
  loop on OS-level blocking calls the platform notification APIs make
  internally.
- Debounce suppression is best-effort and time-window-based, not a
  guarantee of exactly-once delivery per logical change; a caller that
  needs stronger guarantees (e.g. content-hash-based deduplication)
  builds that on top, in a later phase's application logic.

## Rejected: hand-rolled polling

Rejected because it forces a choice between wasted CPU (aggressive
polling intervals) and poor change-detection latency (relaxed
intervals), whereas OS-native notification APIs — which is what
`watchdog` wraps — deliver events with no polling overhead and near
immediate latency. Reimplementing per-OS bindings by hand would also
duplicate a well-solved, actively maintained problem for no benefit over
using `watchdog` directly.
