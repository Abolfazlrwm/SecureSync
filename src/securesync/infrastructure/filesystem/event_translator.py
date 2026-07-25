"""Translation between ``watchdog`` events and domain events.

Isolated in its own module, with no I/O of its own, so it can be unit
tested against directly-constructed ``watchdog`` event objects without
touching a real filesystem.
"""

from __future__ import annotations

from pathlib import Path

from watchdog.events import FileSystemEvent as WatchdogRawEvent

from securesync.domain.events import FileSystemEvent, FileSystemEventType

_EVENT_TYPE_MAP: dict[str, FileSystemEventType] = {
    "created": FileSystemEventType.CREATED,
    "modified": FileSystemEventType.MODIFIED,
    "deleted": FileSystemEventType.DELETED,
    "moved": FileSystemEventType.MOVED,
}

# `watchdog` (via inotify on Linux) also reports file-open/close activity
# that carries no filesystem-*change* information and is out of scope for
# this module. These are routine and expected - effectively one extra
# notification per read/write - not a sign of a translation problem, so
# callers should not treat them the same as a genuinely unrecognized
# event type (see `is_ignorable_event_type`).
_IGNORABLE_EVENT_TYPES = frozenset({"opened", "closed", "closed_no_write"})


def is_ignorable_event_type(raw_event_type: str) -> bool:
    """Whether a raw event type is known, expected, and intentionally unmapped.

    Lets callers distinguish "this is routine noise we don't model" from
    "this is a genuinely unrecognized event type", so they can log the
    former quietly and the latter loudly.

    Args:
        raw_event_type: The `event_type` string from a raw `watchdog` event.

    Returns:
        ``True`` for event types `translate` deliberately does not map
        (e.g. file open/close notifications), ``False`` otherwise.
    """
    return raw_event_type in _IGNORABLE_EVENT_TYPES


def translate(raw_event: WatchdogRawEvent) -> FileSystemEvent:
    """Convert a ``watchdog`` filesystem event into a domain event.

    Args:
        raw_event: The raw event object dispatched by ``watchdog``.

    Returns:
        The equivalent, immutable domain :class:`FileSystemEvent`.

    Raises:
        ValueError: If ``raw_event.event_type`` is not a recognized type.
    """
    try:
        event_type = _EVENT_TYPE_MAP[raw_event.event_type]
    except KeyError as exc:
        raise ValueError(f"Unrecognized watchdog event type: {raw_event.event_type!r}") from exc

    dest_path: Path | None = None
    if event_type is FileSystemEventType.MOVED:
        dest_path = Path(str(raw_event.dest_path))

    return FileSystemEvent(
        event_type=event_type,
        src_path=Path(str(raw_event.src_path)),
        is_directory=bool(raw_event.is_directory),
        dest_path=dest_path,
    )
