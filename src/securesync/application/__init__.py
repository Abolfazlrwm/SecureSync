"""SecureSync — application package.

Use-case orchestration against domain ports; depends on ``domain/`` only.
See docs/architecture.md for what belongs in this layer.

Implemented so far (Phase 1):
    - ``use_cases.monitor_directories``: ``MonitorDirectoriesUseCase``.
    - ``observers.logging_observer``: ``LoggingFileSystemEventObserver``.
"""
