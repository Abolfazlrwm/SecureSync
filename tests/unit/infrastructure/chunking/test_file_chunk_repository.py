"""Unit tests for `securesync.infrastructure.chunking.file_chunk_repository.FileChunkRepository`."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from securesync.domain.chunk import ChunkAlgorithm, ChunkCollection, ChunkHash, ChunkMetadata
from securesync.infrastructure.chunking.file_chunk_repository import FileChunkRepository
from securesync.shared.exceptions import ChunkEngineError
from tests.platform import running_as_root


def _make_collection(source_path: Path, *, with_hashes: bool = True) -> ChunkCollection:
    def _metadata(index: int, size: int, offset: int) -> ChunkMetadata:
        chunk_hash = (
            ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=f"{index:064d}")
            if with_hashes
            else None
        )
        return ChunkMetadata(
            chunk_id=f"chunk-{index}",
            index=index,
            size=size,
            offset=offset,
            chunk_hash=chunk_hash,
        )

    chunks = (_metadata(0, 4, 0), _metadata(1, 4, 4), _metadata(2, 2, 8))
    return ChunkCollection(source_path=source_path, chunk_size=4, total_size=10, chunks=chunks)


@pytest.fixture
def repository(tmp_path: Path) -> FileChunkRepository:
    """A `FileChunkRepository` backed by a fresh temporary storage directory."""
    return FileChunkRepository(storage_dir=tmp_path / "manifests")


class TestSaveAndLoad:
    """Tests for the save/load round trip."""

    def test_load_before_save_returns_none(
        self, repository: FileChunkRepository, tmp_path: Path
    ) -> None:
        """Loading a manifest that was never saved returns `None`, not an error."""
        assert repository.load(tmp_path / "never_saved.bin") is None

    def test_round_trip_preserves_every_field(
        self, repository: FileChunkRepository, tmp_path: Path
    ) -> None:
        """Saving then loading reproduces an equal `ChunkCollection`."""
        source = tmp_path / "file.bin"
        collection = _make_collection(source)

        repository.save(collection)
        loaded = repository.load(source)

        assert loaded == collection

    def test_round_trip_preserves_unhashed_chunks(
        self, repository: FileChunkRepository, tmp_path: Path
    ) -> None:
        """A manifest whose chunks have no recorded hash round-trips `None` correctly."""
        source = tmp_path / "file.bin"
        collection = _make_collection(source, with_hashes=False)

        repository.save(collection)
        loaded = repository.load(source)

        assert loaded is not None
        assert all(chunk.chunk_hash is None for chunk in loaded.chunks)

    def test_round_trip_empty_collection(
        self, repository: FileChunkRepository, tmp_path: Path
    ) -> None:
        """An empty-file manifest (zero chunks) round-trips correctly."""
        source = tmp_path / "empty.bin"
        collection = ChunkCollection(source_path=source, chunk_size=4, total_size=0, chunks=())

        repository.save(collection)
        loaded = repository.load(source)

        assert loaded == collection

    def test_save_creates_storage_directory(self, tmp_path: Path) -> None:
        """The storage directory is created on first save if it doesn't exist."""
        storage_dir = tmp_path / "does" / "not" / "exist" / "yet"
        repository = FileChunkRepository(storage_dir=storage_dir)
        collection = _make_collection(tmp_path / "file.bin")

        repository.save(collection)

        assert storage_dir.is_dir()

    def test_second_save_overwrites_first(
        self, repository: FileChunkRepository, tmp_path: Path
    ) -> None:
        """Saving a new manifest for the same source path replaces the old one."""
        source = tmp_path / "file.bin"
        first = _make_collection(source)
        second = ChunkCollection(source_path=source, chunk_size=4, total_size=0, chunks=())

        repository.save(first)
        repository.save(second)
        loaded = repository.load(source)

        assert loaded == second

    def test_relative_and_absolute_paths_to_same_file_share_a_manifest(
        self, repository: FileChunkRepository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The manifest is keyed by resolved path, not the literal path string given."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "sub").mkdir()
        absolute_path = tmp_path / "sub" / "file.bin"
        relative_path = Path("sub") / "file.bin"

        repository.save(_make_collection(absolute_path))
        loaded = repository.load(relative_path)

        assert loaded is not None
        assert loaded.source_path == absolute_path

    def test_different_files_get_different_manifests(
        self, repository: FileChunkRepository, tmp_path: Path
    ) -> None:
        """Two different source paths never collide onto the same manifest."""
        first_source = tmp_path / "a.bin"
        second_source = tmp_path / "b.bin"
        repository.save(_make_collection(first_source, with_hashes=False))
        repository.save(_make_collection(second_source, with_hashes=True))

        loaded_first = repository.load(first_source)
        loaded_second = repository.load(second_source)

        assert loaded_first is not None
        assert loaded_second is not None
        assert loaded_first.chunks[0].chunk_hash is None
        assert loaded_second.chunks[0].chunk_hash is not None

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits don't apply on Windows")
    @pytest.mark.skipif(running_as_root(), reason="root bypasses permission checks")
    def test_save_failure_raises_chunk_engine_error(self, tmp_path: Path) -> None:
        """A storage directory that can't be created or written raises `ChunkEngineError`."""
        readonly_parent = tmp_path / "readonly"
        readonly_parent.mkdir()
        readonly_parent.chmod(0o555)
        repository = FileChunkRepository(storage_dir=readonly_parent / "manifests")
        try:
            with pytest.raises(ChunkEngineError):
                repository.save(_make_collection(tmp_path / "file.bin"))
        finally:
            readonly_parent.chmod(0o755)


class TestCorruptManifest:
    """Tests for handling an unreadable or malformed manifest on disk."""

    def test_corrupted_json_raises_chunk_engine_error(
        self, repository: FileChunkRepository, tmp_path: Path
    ) -> None:
        """A non-JSON manifest raises `ChunkEngineError`, not a raw parser error."""
        source = tmp_path / "file.bin"
        repository.save(_make_collection(source))
        manifest_path = repository._manifest_path(source)
        manifest_path.write_bytes(b"{ not valid json")

        with pytest.raises(ChunkEngineError):
            repository.load(source)

    def test_manifest_missing_required_field_raises_chunk_engine_error(
        self, repository: FileChunkRepository, tmp_path: Path
    ) -> None:
        """A structurally incomplete manifest raises `ChunkEngineError`."""
        source = tmp_path / "file.bin"
        repository.save(_make_collection(source))
        manifest_path = repository._manifest_path(source)
        manifest_path.write_bytes(b'{"source_path": "file.bin"}')

        with pytest.raises(ChunkEngineError):
            repository.load(source)
