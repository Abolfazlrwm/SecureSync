"""SQLite implementation of the MetadataRepository port."""

from __future__ import annotations

import json
from datetime import datetime

import aiosqlite
import structlog

from securesync.domain.chunk import ChunkHash, ChunkMetadata
from securesync.domain.conflict import VersionVector
from securesync.domain.metadata import FileMetadata, MetadataRepository

logger = structlog.get_logger()


class SqliteMetadataRepository(MetadataRepository):
    """A production-grade SQLite backend for metadata persistence."""

    def __init__(self, database_path: str) -> None:
        self._database_path = database_path
        self._connection: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        """Establish connection and initialize schema."""
        self._connection = await aiosqlite.connect(self._database_path)
        await self._connection.execute("PRAGMA foreign_keys = ON")
        await self._init_db()

    async def _init_db(self) -> None:
        """Initialize the database schema."""
        assert self._connection is not None
        await self._connection.execute("""
            CREATE TABLE IF NOT EXISTS files (
                file_path TEXT PRIMARY KEY,
                version_vector TEXT NOT NULL,
                last_modified TIMESTAMP NOT NULL,
                is_deleted BOOLEAN NOT NULL DEFAULT 0
            )
            """)
        await self._connection.execute("""
            CREATE TABLE IF NOT EXISTS chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                chunk_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                size INTEGER NOT NULL,
                offset INTEGER NOT NULL,
                hash_algo TEXT,
                hash_value TEXT,
                FOREIGN KEY (file_path) REFERENCES files (file_path) ON DELETE CASCADE
            )
            """)
        await self._connection.commit()

    async def save_file_metadata(self, metadata: FileMetadata) -> None:
        """See :meth:`MetadataRepository.save_file_metadata`."""
        assert self._connection is not None

        # Save file record
        await self._connection.execute(
            """
            INSERT OR REPLACE INTO files (file_path, version_vector, last_modified, is_deleted)
            VALUES (?, ?, ?, ?)
            """,
            (
                metadata.file_path,
                json.dumps(metadata.version_vector.counters),
                metadata.last_modified.isoformat(),
                1 if metadata.is_deleted else 0,
            ),
        )

        # Clear existing chunks and save new ones
        await self._connection.execute(
            "DELETE FROM chunks WHERE file_path = ?", (metadata.file_path,)
        )
        for chunk in metadata.chunks:
            hash_algo = chunk.chunk_hash.algorithm if chunk.chunk_hash else None
            hash_value = chunk.chunk_hash.digest if chunk.chunk_hash else None
            await self._connection.execute(
                """
                INSERT INTO chunks (
                    file_path, chunk_id, chunk_index, size, offset, hash_algo, hash_value
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    metadata.file_path,
                    chunk.chunk_id,
                    chunk.index,
                    chunk.size,
                    chunk.offset,
                    hash_algo,
                    hash_value,
                ),
            )
        await self._connection.commit()

    async def get_file_metadata(self, file_path: str) -> FileMetadata | None:
        """See :meth:`MetadataRepository.get_file_metadata`."""
        assert self._connection is not None
        async with self._connection.execute(
            "SELECT version_vector, last_modified, is_deleted FROM files WHERE file_path = ?",
            (file_path,),
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None

            vv_json, lm_iso, is_del = row
            version_vector = VersionVector(json.loads(vv_json))
            last_modified = datetime.fromisoformat(lm_iso)

            chunks = []
            async with self._connection.execute(
                (
                    "SELECT chunk_id, chunk_index, size, offset, hash_algo, hash_value "
                    "FROM chunks WHERE file_path = ? ORDER BY chunk_index"
                ),
                (file_path,),
            ) as chunk_cursor:
                async for c_row in chunk_cursor:
                    cid, idx, size, off, algo, val = c_row
                    chunk_hash = ChunkHash(algo, val) if algo and val else None
                    chunks.append(
                        ChunkMetadata(
                            chunk_id=cid,
                            index=idx,
                            size=size,
                            offset=off,
                            chunk_hash=chunk_hash,
                        )
                    )

            return FileMetadata(
                file_path=file_path,
                version_vector=version_vector,
                last_modified=last_modified,
                is_deleted=bool(is_del),
                chunks=chunks,
            )

    async def list_all_files(self) -> list[FileMetadata]:
        """See :meth:`MetadataRepository.list_all_files`."""
        assert self._connection is not None
        files = []
        async with self._connection.execute("SELECT file_path FROM files") as cursor:
            async for row in cursor:
                metadata = await self.get_file_metadata(row[0])
                if metadata:
                    files.append(metadata)
        return files

    async def delete_file_metadata(self, file_path: str) -> None:
        """See :meth:`MetadataRepository.delete_file_metadata`."""
        assert self._connection is not None
        await self._connection.execute("DELETE FROM files WHERE file_path = ?", (file_path,))
        await self._connection.commit()

    async def begin_transaction(self) -> None:
        """See :meth:`MetadataRepository.begin_transaction`."""
        assert self._connection is not None
        await self._connection.execute("BEGIN")

    async def commit(self) -> None:
        """See :meth:`MetadataRepository.commit`."""
        assert self._connection is not None
        await self._connection.commit()

    async def rollback(self) -> None:
        """See :meth:`MetadataRepository.rollback`."""
        assert self._connection is not None
        await self._connection.rollback()

    async def close(self) -> None:
        """Close the database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None
