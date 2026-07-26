"""Temporary filesystem-backed implementation of the ``ChunkRepository`` port.

A placeholder until the SQLite-backed metadata store planned for
Phase 8 lands (see ``ROADMAP.md``) — the port stays the same either
way, so callers never need to change when that adapter is swapped in.
Each file's manifest is stored as one JSON document, keyed by a hash of
its resolved source path.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import orjson
import structlog

from securesync.domain.chunk import (
    ChunkAlgorithm,
    ChunkCollection,
    ChunkHash,
    ChunkMetadata,
)
from securesync.domain.chunking import ChunkRepository
from securesync.infrastructure.chunking._atomic_write import atomic_write_bytes
from securesync.shared.exceptions import ChunkEngineError

logger = structlog.get_logger(__name__)


class FileChunkRepository(ChunkRepository):
    """Stores each file's chunk manifest as one JSON document on disk."""

    def __init__(self, storage_dir: Path) -> None:
        """Initialize the repository.

        Args:
            storage_dir: Directory manifests are written under. Created
                on first :meth:`save` if it doesn't already exist.
        """
        self._storage_dir = storage_dir

    def save(self, collection: ChunkCollection) -> None:
        """See :meth:`ChunkRepository.save`.

        Writes atomically (see
        :func:`~securesync.infrastructure.chunking._atomic_write.atomic_write_bytes`),
        so a crash or a concurrent :meth:`load` never observes a
        partially written manifest.

        Raises:
            ChunkEngineError: If the storage directory can't be created
                or the manifest can't be written.
        """
        manifest_path = self._manifest_path(collection.source_path)
        try:
            atomic_write_bytes(
                manifest_path, orjson.dumps(_collection_to_dict(collection)), temp_suffix="manifest"
            )
        except OSError as exc:
            raise ChunkEngineError(
                f"Failed to save chunk manifest for {collection.source_path}: {exc}"
            ) from exc
        logger.debug(
            "chunk_manifest_saved",
            source_path=str(collection.source_path),
            chunk_count=collection.chunk_count,
        )

    def load(self, source_path: Path) -> ChunkCollection | None:
        """See :meth:`ChunkRepository.load`.

        Raises:
            ChunkEngineError: If the manifest exists but can't be read
                or is not well-formed.
        """
        manifest_path = self._manifest_path(source_path)
        if not manifest_path.exists():
            return None
        try:
            payload = orjson.loads(manifest_path.read_bytes())
            return _collection_from_dict(payload)
        except (OSError, orjson.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ChunkEngineError(
                f"Failed to load chunk manifest for {source_path}: {exc}"
            ) from exc

    def _manifest_path(self, source_path: Path) -> Path:
        """Return the on-disk manifest path for ``source_path``.

        Keyed by a digest of the resolved (absolute, symlink-free)
        path so the same logical file always maps to the same manifest
        file regardless of how it was referenced (relative vs.
        absolute).
        """
        digest = hashlib.sha256(str(source_path.resolve()).encode("utf-8")).hexdigest()
        return self._storage_dir / f"{digest}.json"


def _collection_to_dict(collection: ChunkCollection) -> dict[str, Any]:
    return {
        "source_path": str(collection.source_path),
        "chunk_size": collection.chunk_size,
        "total_size": collection.total_size,
        "chunks": [_metadata_to_dict(chunk) for chunk in collection.chunks],
    }


def _metadata_to_dict(metadata: ChunkMetadata) -> dict[str, Any]:
    chunk_hash = metadata.chunk_hash
    return {
        "chunk_id": metadata.chunk_id,
        "index": metadata.index,
        "size": metadata.size,
        "offset": metadata.offset,
        "chunk_hash": (
            {"algorithm": chunk_hash.algorithm.value, "digest": chunk_hash.digest}
            if chunk_hash is not None
            else None
        ),
        "created_at": metadata.created_at.isoformat(),
    }


def _collection_from_dict(payload: dict[str, Any]) -> ChunkCollection:
    chunks_payload = cast(list[dict[str, Any]], payload["chunks"])
    return ChunkCollection(
        source_path=Path(cast(str, payload["source_path"])),
        chunk_size=cast(int, payload["chunk_size"]),
        total_size=cast(int, payload["total_size"]),
        chunks=tuple(_metadata_from_dict(item) for item in chunks_payload),
    )


def _metadata_from_dict(payload: dict[str, Any]) -> ChunkMetadata:
    hash_payload = cast(dict[str, Any] | None, payload["chunk_hash"])
    chunk_hash = (
        ChunkHash(
            algorithm=ChunkAlgorithm(hash_payload["algorithm"]),
            digest=cast(str, hash_payload["digest"]),
        )
        if hash_payload is not None
        else None
    )
    return ChunkMetadata(
        chunk_id=cast(str, payload["chunk_id"]),
        index=cast(int, payload["index"]),
        size=cast(int, payload["size"]),
        offset=cast(int, payload["offset"]),
        chunk_hash=chunk_hash,
        created_at=datetime.fromisoformat(cast(str, payload["created_at"])),
    )
