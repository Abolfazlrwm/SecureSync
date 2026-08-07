# ADR 0013: SQLite for Metadata Persistence

**Status:** Accepted
**Date:** 2026-07-30

## Context

Phase 8 requires replacing the temporary JSON-based persistence with a production-grade backend. We need to store file metadata, chunk mappings, peer information, and version history.

## Decision

1.  **SQLite Backend**: We will use SQLite as the primary metadata store. SQLite is serverless, zero-configuration, and highly reliable, making it ideal for a local synchronization engine.
2.  **Asynchronous Access**: We will use `aiosqlite` to ensure that database I/O does not block the main event loop.
3.  **Relational Schema**:
    *   `files`: Stores file paths, version vectors, and status.
    *   `chunks`: Stores individual chunk metadata with a foreign key to `files`.
4.  **Repository Pattern**: All database access is encapsulated within `SqliteMetadataRepository`, implementing the `MetadataRepository` port. No SQLite-specific logic or types are exposed to the domain or application layers.
5.  **Transactions**: We support atomic operations through explicit transaction management in the repository port.

## Consequences

### Positive
- **Reliability**: SQLite provides ACID compliance and robust crash recovery.
- **Performance**: Relational indexing allows for efficient querying of large file sets.
- **Scalability**: Can easily handle tens of thousands of files and millions of chunks.

### Negative / Trade-offs
- **Complexity**: Managing database schemas and migrations is more complex than simple file writes.
- **Dependency**: Adds a dependency on `aiosqlite` and `sqlite3`.
