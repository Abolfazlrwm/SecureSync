"""Unit tests for conflict resolution use cases."""

import pytest

from securesync.application.use_cases.conflict_resolution import (
    DetectConflictUseCase,
    LastWriterWinsStrategy,
    ResolveConflictUseCase,
)
from securesync.domain.conflict import VersionVector
from securesync.domain.conflict_exceptions import ConflictNotFoundError
from securesync.infrastructure.networking.in_memory_conflict_repository import (
    InMemoryConflictRepository,
)


@pytest.mark.asyncio
async def test_detect_conflict_concurrent_versions() -> None:
    repo = InMemoryConflictRepository()
    use_case = DetectConflictUseCase(repo)

    local = VersionVector({"dev-1": 2, "dev-2": 1})
    remote = VersionVector({"dev-1": 1, "dev-2": 2})

    conflict = await use_case.execute("test.txt", local, remote, "dev-2")

    assert conflict is not None
    assert conflict.file_path == "test.txt"
    assert len(await repo.list_active()) == 1


@pytest.mark.asyncio
async def test_detect_no_conflict_ancestor_version() -> None:
    repo = InMemoryConflictRepository()
    use_case = DetectConflictUseCase(repo)

    local = VersionVector({"dev-1": 1})
    remote = VersionVector({"dev-1": 2})

    conflict = await use_case.execute("test.txt", local, remote, "dev-2")

    assert conflict is None
    assert len(await repo.list_active()) == 0


@pytest.mark.asyncio
async def test_resolve_conflict_use_case() -> None:
    repo = InMemoryConflictRepository()
    strategy = LastWriterWinsStrategy()
    use_case = ResolveConflictUseCase(repo, strategy)

    local = VersionVector({"a": 1})
    remote = VersionVector({"b": 1})

    detect_use_case = DetectConflictUseCase(repo)
    conflict = await detect_use_case.execute("test.txt", local, remote, "dev-2")

    assert conflict is not None

    import copy
    from datetime import timedelta

    remote_metadata = copy.deepcopy(conflict)
    # Simulate remote being later
    object.__setattr__(remote_metadata, "detected_at", conflict.detected_at + timedelta(seconds=1))

    result = await use_case.execute(conflict.conflict_id, remote_metadata)

    assert result is True
    assert len(await repo.list_active()) == 0


@pytest.mark.asyncio
async def test_resolve_unknown_conflict_id_raises_conflict_not_found() -> None:
    """Resolving a conflict_id absent from the repository raises a domain error."""
    repo = InMemoryConflictRepository()
    strategy = LastWriterWinsStrategy()
    use_case = ResolveConflictUseCase(repo, strategy)

    detect_use_case = DetectConflictUseCase(repo)
    local = VersionVector({"a": 1})
    remote = VersionVector({"b": 1})
    remote_metadata = await detect_use_case.execute("test.txt", local, remote, "dev-2")
    assert remote_metadata is not None

    with pytest.raises(ConflictNotFoundError):
        await use_case.execute("does-not-exist", remote_metadata)
