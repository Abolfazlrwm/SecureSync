"""SecureSync — infrastructure package.

Concrete adapters implementing domain ports. See docs/architecture.md
for what belongs in this layer.

Implemented so far:
    Phase 1 (Filesystem Watcher):
        - ``filesystem.watchdog_watcher``: ``WatchdogFileWatcher``, the
          ``watchdog``-based implementation of ``domain.watcher.FileWatcher``.
    Phase 2 (Chunk Engine):
        - ``chunking.streaming_chunk_reader``: ``FixedSizeChunkingStrategy``
          and ``StreamingChunkReader``, implementing
          ``domain.chunking.ChunkingStrategy`` and ``ChunkReader``.
        - ``chunking.sha256_hash_provider``: ``SHA256HashProvider``,
          implementing ``domain.chunking.ChunkHasher``.
        - ``chunking.chunk_file_writer``: ``ChunkFileWriter``,
          implementing ``domain.chunking.ChunkWriter``.
        - ``chunking.file_chunk_repository``: ``FileChunkRepository``,
          a temporary filesystem-backed implementation of
          ``domain.chunking.ChunkRepository``.
"""
