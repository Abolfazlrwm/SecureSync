# ADR 0014: Synchronization Orchestrator State Machine

**Status:** Accepted
**Date:** 2026-07-30

## Context

SecureSync involves multiple asynchronous components (discovery, transfer, watcher, etc.). We need a central orchestrator to manage the lifecycle and state of the synchronization process.

## Decision

1.  **SyncOrchestrator**: A central application service that coordinates all use cases and infrastructure adapters.
2.  **State Machine**: The orchestrator implements a state machine (`IDLE`, `SCANNING`, `SYNCING`, `PAUSED`, `ERROR`) to manage transitions and ensure consistent behavior.
3.  **Aggregated Metrics**: A `SyncStats` object tracks performance and health metrics across all components.
4.  **Graceful Lifecycle**: The orchestrator provides `start`, `stop`, `pause`, and `resume` methods with proper handling of background tasks and cancellation.
5.  **Event-Driven Coordination**: The orchestrator reacts to domain events (e.g., peer discovery, file changes) to trigger appropriate synchronization actions.

## Consequences

### Positive
- **Centralized Control**: Provides a single entry point for controlling the synchronization engine.
- **Observability**: Centralized metrics and state tracking make it easier to monitor the system's health.
- **Robustness**: Proper state management prevents illegal transitions and handles errors gracefully.

### Negative / Trade-offs
- **Coupling**: The orchestrator is naturally coupled to many other components, as its job is to coordinate them.
- **Complexity**: Managing concurrent background tasks and state transitions requires careful implementation of async patterns.
