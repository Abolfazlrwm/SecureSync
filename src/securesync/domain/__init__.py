"""SecureSync — domain package.

Entities, value objects, and ports (interfaces). Pure Python only — no
I/O, no third-party dependency. See docs/architecture.md for what
belongs in this layer.

Implemented so far:
    Phase 1 (Filesystem Watcher):
        - ``events``: ``FileSystemEvent``, ``FileSystemEventType``.
        - ``watcher``: the ``FileWatcher`` port and the
          ``FileSystemEventObserver`` protocol (Observer pattern).
        - ``exceptions``: filesystem-watcher domain errors.
    Phase 2 (Chunk Engine):
        - ``chunk``: ``Chunk``, ``ChunkHash``, ``ChunkMetadata``,
          ``ChunkCollection``, ``ChunkAlgorithm`` value objects.
        - ``chunking``: the ``ChunkingStrategy`` (Strategy pattern),
          ``ChunkReader``, ``ChunkHasher``, ``ChunkWriter``, and
          ``ChunkRepository`` ports.
        - ``chunk_exceptions``: chunk-engine domain errors.
"""
