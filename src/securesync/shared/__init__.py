"""SecureSync — shared package.

Cross-cutting exceptions, common types, constants. Depends on nothing.
See docs/architecture.md for what belongs in this layer.

Implemented so far:
    Phase 1 (Filesystem Watcher):
        - ``exceptions``: ``SecureSyncError`` (base) and ``FileWatcherError``.
    Phase 2 (Chunk Engine):
        - ``exceptions``: ``ChunkEngineError``.
"""
