"""SecureSync — application package.

Use-case orchestration against domain ports; depends on ``domain/``
only. See docs/architecture.md for what belongs in this layer.

Implemented so far:
    Phase 1 (Filesystem Watcher):
        - ``use_cases.monitor_directories``: ``MonitorDirectoriesUseCase``.
        - ``observers.logging_observer``: ``LoggingFileSystemEventObserver``.
    Phase 2 (Chunk Engine):
        - ``use_cases.chunk_file``: ``ChunkFileUseCase``.
        - ``use_cases.verify_chunk``: ``VerifyChunkUseCase``.
        - ``use_cases.calculate_chunk_hashes``: ``CalculateChunkHashesUseCase``.
"""
