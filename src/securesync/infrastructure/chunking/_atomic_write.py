"""Internal helper: atomic file writes shared by chunk-engine infrastructure adapters.

Not a port implementation itself — a small utility used by both
``ChunkFileWriter`` and ``FileChunkRepository`` so every file the chunk
engine writes to disk (a chunk's bytes, a manifest) is written the same
safe way, without duplicating the temp-file/fsync/rename logic twice.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path


def atomic_write_bytes(destination: Path, data: bytes, *, temp_suffix: str) -> None:
    """Write ``data`` to ``destination`` atomically.

    Creates missing parent directories, writes to a temporary sibling
    file, ``fsync``s it, then renames it into place — so a crash or a
    concurrent reader never observes a partially written file at
    ``destination``. On failure, the temporary file is removed on a
    best-effort basis; a failure during that cleanup is swallowed so it
    can never mask the original error being propagated to the caller.

    Args:
        destination: Final path to write to. Overwritten if it exists.
        data: Bytes to write.
        temp_suffix: Appended to the temporary file's name, so
            concurrent writes to different destinations never collide
            on the same temp path.

    Raises:
        OSError: If creating the parent directory, writing, `fsync`ing,
            or renaming fails. Callers are expected to translate this
            into their own domain or shared exception type.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = destination.with_name(f".{destination.name}.tmp-{temp_suffix}")
    try:
        with tmp_path.open("wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        tmp_path.replace(destination)
    except OSError:
        with contextlib.suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        raise
