"""SecureSync — infrastructure package.

Concrete adapters implementing domain ports. See docs/architecture.md
for what belongs in this layer.

Implemented so far (Phase 1):
    - ``filesystem.watchdog_watcher``: ``WatchdogFileWatcher``, the
      ``watchdog``-based implementation of ``domain.watcher.FileWatcher``.
"""
