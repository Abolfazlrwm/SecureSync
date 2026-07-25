"""SecureSync — domain package.

Entities, value objects, and ports (interfaces). Pure Python only — no
I/O, no third-party dependency. See docs/architecture.md for what
belongs in this layer.

Implemented so far (Phase 1):
    - ``events``: ``FileSystemEvent``, ``FileSystemEventType``.
    - ``watcher``: the ``FileWatcher`` port and the ``FileSystemEventObserver``
      protocol (Observer pattern).
    - ``exceptions``: filesystem-watcher domain errors.
"""
