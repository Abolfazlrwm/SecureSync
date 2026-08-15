"""JSON-on-disk implementation of the TrustedPeerRepository port.

One JSON document for the whole trust store (device_id -> hex-encoded
public key), atomically rewritten on every :meth:`FileTrustedPeerRepository.trust`
call — the same atomic-write shape used elsewhere in this codebase
(temp file, fsync, rename), kept as a small local copy here rather
than imported from ``infrastructure/chunking/_atomic_write.py``, which
is explicitly scoped to chunk-engine adapters.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path

from securesync.domain.identity import TrustedPeerRepository


class FileTrustedPeerRepository(TrustedPeerRepository):
    """A JSON-file-backed, atomically-written trusted-peer key store."""

    def __init__(self, storage_path: Path) -> None:
        """Initialize the repository.

        Args:
            storage_path: Path to the JSON file this repository reads
                and writes. Its parent directory is created on first
                write if missing.
        """
        self._storage_path = storage_path

    async def get_trusted_key(self, device_id: str) -> bytes | None:
        """Return the pinned public key for `device_id`, or None if never seen.

        Args:
            device_id: The peer device ID to look up.

        Returns:
            The pinned raw Ed25519 public key, or None if this is the
            first time `device_id` has been seen.
        """
        store = self._load()
        hex_key = store.get(device_id)
        return bytes.fromhex(hex_key) if hex_key is not None else None

    async def trust(self, device_id: str, public_key: bytes) -> None:
        """Pin `public_key` as trusted for `device_id`.

        Args:
            device_id: The peer device ID to pin a key for.
            public_key: The raw Ed25519 public key to pin.
        """
        store = self._load()
        store[device_id] = public_key.hex()
        self._save(store)

    def _load(self) -> dict[str, str]:
        """Read the trust store, returning an empty one if it doesn't exist yet."""
        if not self._storage_path.exists():
            return {}
        data: dict[str, str] = json.loads(self._storage_path.read_text(encoding="utf-8"))
        return data

    def _save(self, store: dict[str, str]) -> None:
        """Write the trust store atomically."""
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(store, indent=2, sort_keys=True).encode("utf-8")
        tmp_path = self._storage_path.with_name(f".{self._storage_path.name}.tmp")
        try:
            with tmp_path.open("wb") as file:
                file.write(payload)
                file.flush()
                os.fsync(file.fileno())
            tmp_path.replace(self._storage_path)
        except OSError:
            with contextlib.suppress(OSError):
                tmp_path.unlink(missing_ok=True)
            raise
