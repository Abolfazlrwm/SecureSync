"""Unit tests for SqliteMetadataRepository."""

from datetime import UTC, datetime

import pytest
import pytest_asyncio

from securesync.domain.chunk import ChunkHash, ChunkMetadata
from securesync.domain.conflict import VersionVector
from securesync.domain.metadata import FileMetadata
from securesync.infrastructure.metadata.sqlite_metadata_repository import SqliteMetadataRepository


@pytest_asyncio.fixture
async def repo(tmp_path):
    db_path = str(tmp_path / "test_metadata.db")
    repo = SqliteMetadataRepository(db_path)
    await repo.connect()
    yield repo
    await repo.close()


@pytest.mark.asyncio
async def test_save_and_get_file_metadata(repo):
    metadata = FileMetadata(
        file_path="test.txt",
        version_vector=VersionVector({"dev-1": 1}),
        last_modified=datetime.now(UTC),
        chunks=[
            ChunkMetadata(
                chunk_id="c1",
                index=0,
                size=10,
                offset=0,
                chunk_hash=ChunkHash("sha256", "a" * 64),
            )
        ],
    )

    await repo.save_file_metadata(metadata)
    retrieved = await repo.get_file_metadata("test.txt")

    assert retrieved is not None
    assert retrieved.file_path == "test.txt"
    assert retrieved.version_vector.counters == {"dev-1": 1}
    assert len(retrieved.chunks) == 1
    assert retrieved.chunks[0].chunk_id == "c1"


@pytest.mark.asyncio
async def test_list_all_files(repo):
    m1 = FileMetadata("f1.txt", VersionVector(), datetime.now(UTC))
    m2 = FileMetadata("f2.txt", VersionVector(), datetime.now(UTC))

    await repo.save_file_metadata(m1)
    await repo.save_file_metadata(m2)

    files = await repo.list_all_files()
    assert len(files) == 2
    paths = {f.file_path for f in files}
    assert paths == {"f1.txt", "f2.txt"}


@pytest.mark.asyncio
async def test_delete_file_metadata(repo):
    m = FileMetadata("f1.txt", VersionVector(), datetime.now(UTC))
    await repo.save_file_metadata(m)

    await repo.delete_file_metadata("f1.txt")
    retrieved = await repo.get_file_metadata("f1.txt")
    assert retrieved is None
