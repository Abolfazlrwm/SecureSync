"""A basic observer that logs every filesystem event it receives."""

from __future__ import annotations

import structlog

from securesync.domain.events import FileSystemEvent

logger = structlog.get_logger(__name__)


class LoggingFileSystemEventObserver:
    """Observer that logs every filesystem event it receives.

    Serves as the minimal reference implementation of
    ``securesync.domain.watcher.FileSystemEventObserver`` and as a
    development/debugging aid until real consumers (chunk engine,
    metadata indexer) exist in later phases.
    """

    async def on_file_event(self, event: FileSystemEvent) -> None:
        """Log a single filesystem event at INFO level.

        Args:
            event: The filesystem event to log.
        """
        logger.info(
            "filesystem_event",
            event_type=event.event_type.value,
            path=str(event.src_path),
            dest_path=str(event.dest_path) if event.dest_path is not None else None,
            is_directory=event.is_directory,
            is_rename=event.is_rename,
        )
