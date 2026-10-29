"""Integrity attacks against the push receiver.

The receiver used to write whatever bytes arrived, at whatever offset the
sender named, with no check that the content matched the digest the
sender had declared. These tests send pushes whose bytes, bounds, or
bookkeeping are hostile and assert on the effect: nothing unverifiable
reaches the sync root, and no half-written file is ever left at a name
that looks complete.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from securesync.application.use_cases.receive_pushed_files import (
    PushLimits,
    ReceivePushedFilesUseCase,
)
from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.domain.transfer import IncomingPush
from securesync.infrastructure.chunking.local_file_reconstructor import LocalFileReconstructor
from securesync.infrastructure.chunking.sha256_hash_provider import SHA256HashProvider
from tests.doubles import FakeMetadataRepository, FakeTransferTransport

_DEVICE_ID = "receiver"


def _chunk(
    data: bytes,
    *,
    index: int = 0,
    offset: int = 0,
    declared_digest: str | None = None,
    has_hash: bool = True,
) -> Chunk:
    """Build a chunk, optionally lying about its digest or omitting one entirely."""
    chunk_hash = None
    if has_hash:
        if declared_digest is not None:
            declared = declared_digest
        else:
            declared = hashlib.sha256(data).hexdigest()
        chunk_hash = ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=declared)
    return Chunk(
        metadata=ChunkMetadata(
            chunk_id=f"chunk-{index}",
            index=index,
            size=len(data),
            offset=offset,
            chunk_hash=chunk_hash,
        ),
        data=data,
    )


def _push(
    relative_path: str,
    chunk: Chunk,
    *,
    total_chunks: int = 1,
) -> IncomingPush:
    return IncomingPush(relative_path=relative_path, total_chunks=total_chunks, chunk=chunk)


def _receiver(
    sync_root: Path,
    pushes: list[IncomingPush],
    *,
    limits: PushLimits | None = None,
) -> tuple[ReceivePushedFilesUseCase, FakeMetadataRepository]:
    transport = FakeTransferTransport()
    transport.pushes.extend(pushes)
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


def _assert_nothing_written(sync_root: Path, metadata: FakeMetadataRepository) -> None:
    """No file at all, and no temporary assembly file left behind."""
    assert list(sync_root.rglob("*")) == [], "rejected push left files in the sync root"
    assert list(sync_root.rglob("*.part")) == []
    assert metadata.saved == []


class TestChunkIntegrity:
    async def test_chunk_whose_bytes_do_not_match_its_digest_is_rejected(
        self, tmp_path: Path
    ) -> None:
        """The core integrity attack: promise one hash, send other bytes.

        Accepting this lets a peer store arbitrary content under a name
        and digest that other peers will then fetch and trust — the
        manifest and the bytes on disk no longer agree.
        """
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        lying = _chunk(
            b"actual bytes", declared_digest=hashlib.sha256(b"promised bytes").hexdigest()
        )

        use_case, metadata = _receiver(sync_root, [_push("evil.txt", lying)])
        await use_case.run_forever()

        _assert_nothing_written(sync_root, metadata)

    async def test_chunk_without_a_digest_is_rejected(self, tmp_path: Path) -> None:
        """An unhashed chunk cannot be verified, so it must not be stored."""
        sync_root = tmp_path / "sync"
        sync_root.mkdir()

        use_case, metadata = _receiver(
            sync_root, [_push("unverifiable.txt", _chunk(b"data", has_hash=False))]
        )
        await use_case.run_forever()

        _assert_nothing_written(sync_root, metadata)

    async def test_one_tampered_chunk_prevents_the_whole_file_being_committed(
        self, tmp_path: Path
    ) -> None:
        """A file is all-or-nothing, not 'most of it'.

        The first chunk is genuine and gets written to the temporary
        file; the second is tampered. The file must not appear at its
        real path in any form, and the temporary file must be cleaned
        up when the transfer is abandoned.
        """
        sync_root = tmp_path / "sync"
        sync_root.mkdir()

        good = _chunk(b"AAAAAAAA", index=0, offset=0)
        bad = _chunk(b"BBBBBBBB", index=1, offset=8, declared_digest="0" * 64)

        use_case, metadata = _receiver(
            sync_root,
            [_push("mixed.txt", good, total_chunks=2), _push("mixed.txt", bad, total_chunks=2)],
        )
        await use_case.run_forever()

        _assert_nothing_written(sync_root, metadata)


class TestPushBounds:
    async def test_oversized_chunk_is_rejected(self, tmp_path: Path) -> None:
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        limits = PushLimits(max_chunk_size=16)

        use_case, metadata = _receiver(
            sync_root,
            [_push("big.txt", _chunk(b"A" * 32))],
            limits=limits,
        )
        await use_case.run_forever()

        _assert_nothing_written(sync_root, metadata)

    async def test_absurd_offset_cannot_create_a_huge_sparse_file(self, tmp_path: Path) -> None:
        """A 1 TiB offset with a 4-byte chunk would otherwise 'create' a 1 TiB file."""
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        limits = PushLimits(max_file_size=1024)

        use_case, metadata = _receiver(
            sync_root,
            [_push("sparse.bin", _chunk(b"AAAA", offset=1 << 40))],
            limits=limits,
        )
        await use_case.run_forever()

        _assert_nothing_written(sync_root, metadata)

    async def test_zero_total_chunks_is_rejected(self, tmp_path: Path) -> None:
        """``total_chunks=0`` would make the receiver commit an empty file immediately."""
        sync_root = tmp_path / "sync"
        sync_root.mkdir()

        use_case, metadata = _receiver(
            sync_root, [_push("empty.txt", _chunk(b"data"), total_chunks=0)]
        )
        await use_case.run_forever()

        _assert_nothing_written(sync_root, metadata)

    async def test_excessive_total_chunks_is_rejected(self, tmp_path: Path) -> None:
        """Bounds the bookkeeping a peer can force per file."""
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        limits = PushLimits(max_total_chunks=8)

        use_case, metadata = _receiver(
            sync_root,
            [_push("many.txt", _chunk(b"data"), total_chunks=9)],
            limits=limits,
        )
        await use_case.run_forever()

        _assert_nothing_written(sync_root, metadata)
