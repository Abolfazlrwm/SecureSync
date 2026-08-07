# ADR 0012: Conflict Resolution with Version Vectors

**Status:** Accepted
**Date:** 2026-07-30

## Context

SecureSync is a peer-to-peer system where concurrent modifications to the same file can occur on different devices. We need a way to detect these conflicts and provide a mechanism for resolution.

## Decision

1.  **Version Vectors**: We will use Version Vectors (a form of logical clocks) to track causal relationships between file versions. This allows us to distinguish between ancestor-descendant relationships (where one version clearly follows another) and concurrent modifications (conflicts).
2.  **Conflict Detection**: A conflict is detected when two version vectors are concurrent (neither is less than or equal to the other).
3.  **Conflict Metadata**: We introduce `ConflictMetadata` to record the details of a detected conflict, including the local and remote versions and the peer involved.
4.  **Pluggable Merge Strategies**: We define a `MergeStrategy` port to allow different policies for automatic conflict resolution (e.g., Last Writer Wins).
5.  **Conflict Repository**: A `ConflictRepository` port is introduced to persist active conflicts until they are resolved, either automatically or by the user.

## Consequences

### Positive
- **Causal Accuracy**: Version vectors provide a robust way to detect concurrent changes without relying on synchronized physical clocks.
- **Flexibility**: The strategy pattern for merging allows the system to adapt to different user preferences or file types.
- **Auditability**: Persisting conflict metadata ensures that conflicts are not silently ignored and can be audited.

### Negative / Trade-offs
- **Metadata Overhead**: Version vectors grow with the number of devices that have modified a file. For small clusters, this is negligible.
- **Complexity**: Implementing and testing causal consistency is more complex than simple timestamp-based approaches.
