"""Unit tests for ReceivePushedFilesUseCase's assembly lifecycle.

Covers the guarantees that make a push safe to accept from an untrusted
peer: a file appears only when complete, an interrupted transfer never
corrupts what is already on disk, and abandoned temporary files are
cleaned up rather than accumulating.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import time
from collections.abc import AsyncIterator
from pathlib import Path

from securesync.application.use_cases.receive_pushed_files import (
    PushLimits,
    ReceivePushedFilesUseCase,
    _PendingFile,
)
from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.domain.transfer import IncomingPush
from securesync.infrastructure.chunking.local_file_reconstructor import LocalFileReconstructor
from securesync.infrastructure.chunking.sha256_hash_provider import SHA256HashProvider
from tests.doubles import FakeMetadataRepository, FakeTransferTransport

_DEVICE_ID = "receiver"


class _OpenEndedTransport(FakeTransferTransport):
    """A transport whose push stream stays open, so `run_forever` keeps running.

    `FakeTransferTransport` exhausts a fixed list and returns, which
    ends `run_forever` — fine for most tests, but useless for observing
    a receiver that is still mid-transfer.
    """

    def __init__(self) -> None:
        super().__init__()
        self.queue: asyncio.Queue[IncomingPush] = asyncio.Queue()

    async def receive_pushes(self) -> AsyncIterator[IncomingPush]:
        while True:
            yield await self.queue.get()


def _chunk(data: bytes, *, index: int = 0, offset: int = 0) -> Chunk:
    return Chunk(
        metadata=ChunkMetadata(
            chunk_id=f"chunk-{index}",
            index=index,
            size=len(data),
            offset=offset,
            chunk_hash=ChunkHash(
                algorithm=ChunkAlgorithm.SHA256, digest=hashlib.sha256(data).hexdigest()
            ),
        ),
        data=data,
    )


def _push(relative_path: str, chunk: Chunk, *, total_chunks: int) -> IncomingPush:
    return IncomingPush(relative_path=relative_path, total_chunks=total_chunks, chunk=chunk)


def _receiver(
    sync_root: Path,
    transport: FakeTransferTransport,
    *,
    limits: PushLimits | None = None,
) -> tuple[ReceivePushedFilesUseCase, FakeMetadataRepository]:
    metadata = FakeMetadataRepository()
    use_case = ReceivePushedFilesUseCase(
        transport=transport,
        sync_root=sync_root,
        file_reconstructor=LocalFileReconstructor(),
        metadata_repo=metadata,
        own_device_id=_DEVICE_ID,
        hasher=SHA256HashProvider(),
        limits=limits,
    )
    return use_case, metadata


def _partials(sync_root: Path) -> list[Path]:
    return list(sync_root.rglob("*.part"))


class TestAtomicCommit:
    async def test_completed_push_appears_whole(self, tmp_path: Path) -> None:
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        transport = FakeTransferTransport()
        transport.pushes.extend(
            [
                _push("notes.txt", _chunk(b"AAAA", index=0, offset=0), total_chunks=2),
                _push("notes.txt", _chunk(b"BBBB", index=1, offset=4), total_chunks=2),
            ]
        )
        use_case, metadata = _receiver(sync_root, transport)

        await use_case.run_forever()

        assert (sync_root / "notes.txt").read_bytes() == b"AAAABBBB"
        assert _partials(sync_root) == []
        assert [m.file_path for m in metadata.saved] == ["notes.txt"]

    async def test_incomplete_push_leaves_existing_file_untouched(self, tmp_path: Path) -> None:
        """A stalled delta push must not degrade a file that is already correct.

        The chunks are written into a temporary copy; the real file is
        only replaced on completion. Without that, a transfer that
        stops halfway leaves the user with a file that is partly the
        old version and partly the new one — a state that was never a
        valid version of anything.
        """
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        destination = sync_root / "notes.txt"
        destination.write_bytes(b"OLD CONTENT!")

        transport = FakeTransferTransport()
        transport.pushes.append(
            _push("notes.txt", _chunk(b"NEW", index=0, offset=0), total_chunks=2)
        )
        use_case, metadata = _receiver(sync_root, transport)

        await use_case.run_forever()

        assert destination.read_bytes() == b"OLD CONTENT!"
        assert _partials(sync_root) == []
        assert metadata.saved == []

    async def test_incomplete_push_creates_no_file(self, tmp_path: Path) -> None:
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        transport = FakeTransferTransport()
        transport.pushes.append(
            _push("new.txt", _chunk(b"AAAA", index=0, offset=0), total_chunks=3)
        )
        use_case, _ = _receiver(sync_root, transport)

        await use_case.run_forever()

        assert not (sync_root / "new.txt").exists()
        assert _partials(sync_root) == []

    async def test_duplicate_chunk_does_not_complete_a_file_with_a_hole(
        self, tmp_path: Path
    ) -> None:
        """Counting arrivals instead of distinct indices would commit a hole here.

        Two chunks are expected; the same index arrives twice. A plain
        counter reaches 2 and finalizes a file whose second half was
        never received.
        """
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        transport = FakeTransferTransport()
        transport.pushes.extend(
            [
                _push("hole.txt", _chunk(b"AAAA", index=0, offset=0), total_chunks=2),
                _push("hole.txt", _chunk(b"AAAA", index=0, offset=0), total_chunks=2),
            ]
        )
        use_case, metadata = _receiver(sync_root, transport)

        await use_case.run_forever()

        assert not (sync_root / "hole.txt").exists()
        assert metadata.saved == []


class TestCleanup:
    async def test_cancellation_discards_partial_files(self, tmp_path: Path) -> None:
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        transport = _OpenEndedTransport()
        use_case, _ = _receiver(sync_root, transport)

        task = asyncio.create_task(use_case.run_forever())
        await transport.queue.put(_push("big.bin", _chunk(b"AAAA", index=0), total_chunks=4))
        # Let the chunk be processed and the temporary file created.
        for _ in range(50):
            await asyncio.sleep(0.01)
            if _partials(sync_root):
                break
        assert _partials(sync_root), "expected a partial file before cancelling"

        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

        assert _partials(sync_root) == []
        assert not (sync_root / "big.bin").exists()

    async def test_expired_partial_is_discarded(self, tmp_path: Path) -> None:
        """The sweeper's body, called directly so the test does not race a timer.

        `_abort_expired_partials` is what the periodic sweeper invokes;
        calling it directly keeps this deterministic while still
        exercising the real expiry decision and the real cleanup.
        """
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        destination = sync_root / "stalled.bin"
        partial = LocalFileReconstructor().begin_partial(destination)
        assert partial.exists()

        use_case, _ = _receiver(sync_root, FakeTransferTransport())
        stalled = _PendingFile(partial=partial, received_indices={0})
        stalled.last_activity = time.monotonic() - 3600.0
        use_case._pending["stalled.bin"] = stalled

        use_case._abort_expired_partials()

        assert not partial.exists()
        assert "stalled.bin" not in use_case._pending

    async def test_fresh_partial_is_not_swept(self, tmp_path: Path) -> None:
        """The sweeper must only discard stalled transfers, never active ones."""
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        partial = LocalFileReconstructor().begin_partial(sync_root / "active.bin")

        use_case, _ = _receiver(sync_root, FakeTransferTransport())
        use_case._pending["active.bin"] = _PendingFile(partial=partial, received_indices={0})

        use_case._abort_expired_partials()

        assert partial.exists()
        assert "active.bin" in use_case._pending

    async def test_refuses_to_track_unbounded_partial_files(self, tmp_path: Path) -> None:
        """A peer cannot make this device hold an unlimited number of open assemblies."""
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        transport = FakeTransferTransport()
        transport.pushes.extend(
            [
                _push("first.bin", _chunk(b"AAAA", index=0), total_chunks=4),
                _push("second.bin", _chunk(b"AAAA", index=0), total_chunks=4),
            ]
        )
        use_case, metadata = _receiver(sync_root, transport, limits=PushLimits(max_pending_files=1))

        await use_case.run_forever()

        assert not (sync_root / "second.bin").exists()
        assert metadata.saved == []
