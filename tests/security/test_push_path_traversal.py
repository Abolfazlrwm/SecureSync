"""Path-traversal attacks against the autonomous push receiver.

`ReceivePushedFilesUseCase` turns a peer-supplied `relative_path` into a
real filesystem path and writes chunk bytes there. Before this suite
existed, that join was a bare `sync_root / incoming.relative_path` with
no validation at all, so a peer could name any path it liked and have
the receiver write outside the sync root.

Each test here drives the real use case and the real
`LocalFileReconstructor` against a real temporary directory. The only
double is the transport, which stands in for "bytes arrived from a
peer" — everything that decides where those bytes land is production
code.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from securesync.application.use_cases.receive_pushed_files import ReceivePushedFilesUseCase
from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkHash, ChunkMetadata
from securesync.domain.transfer import IncomingPush
from securesync.infrastructure.chunking.local_file_reconstructor import LocalFileReconstructor
from tests.doubles import FakeMetadataRepository, FakeTransferTransport

_DEVICE_ID = "receiver"


def _chunk(data: bytes, *, index: int = 0, offset: int = 0) -> Chunk:
    """Build a chunk carrying a genuine SHA-256 of its own data.

    The hash is real rather than absent on purpose: once the push path
    verifies chunk integrity, an unhashed chunk is rejected for *that*
    reason, which would let these tests pass without ever reaching the
    path-validation logic they exist to exercise.
    """
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


def _push(relative_path: str, data: bytes, *, total_chunks: int = 1) -> IncomingPush:
    """Build a single-chunk push naming ``relative_path``."""
    return IncomingPush(
        relative_path=relative_path,
        total_chunks=total_chunks,
        chunk=_chunk(data),
    )


def _receiver(
    sync_root: Path, pushes: list[IncomingPush]
) -> tuple[ReceivePushedFilesUseCase, FakeMetadataRepository]:
    """Wire a real receiver over a fake transport preloaded with ``pushes``."""
    transport = FakeTransferTransport()
    transport.pushes.extend(pushes)
    metadata = FakeMetadataRepository()
    use_case = ReceivePushedFilesUseCase(
        transport=transport,
        sync_root=sync_root,
        file_reconstructor=LocalFileReconstructor(),
        metadata_repo=metadata,
        own_device_id=_DEVICE_ID,
    )
    return use_case, metadata


class TestPushPathTraversal:
    """A peer must never be able to choose a write target outside the sync root."""

    async def test_dotdot_relative_path_cannot_escape_sync_root(self, tmp_path: Path) -> None:
        """The original proof of concept: ``../escaped.txt``.

        The receiver writes to ``sync_root / relative_path``; with no
        validation, ``../escaped.txt`` resolves to the directory *above*
        the sync root, so a peer writes a file the user never chose to
        share, in a directory SecureSync does not own.
        """
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        escaped = tmp_path / "escaped.txt"

        use_case, metadata = _receiver(sync_root, [_push("../escaped.txt", b"pwned")])
        await use_case.run_forever()

        assert not escaped.exists(), "peer escaped the sync root via '..'"
        assert metadata.saved == [], "rejected push must not record metadata"

    async def test_absolute_path_cannot_escape_sync_root(self, tmp_path: Path) -> None:
        """An absolute path replaces the sync root entirely when joined."""
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        target = tmp_path / "absolute.txt"

        use_case, metadata = _receiver(sync_root, [_push(str(target), b"pwned")])
        await use_case.run_forever()

        assert not target.exists(), "peer escaped the sync root via an absolute path"
        assert metadata.saved == []

    async def test_symlinked_directory_cannot_escape_sync_root(self, tmp_path: Path) -> None:
        """A symlink *inside* the sync root that points outside it.

        String-prefix checks pass here — the joined path really does
        start with the sync root — while the bytes still land in a
        directory outside it. Only resolving the path and comparing
        real locations catches this.
        """
        sync_root = tmp_path / "sync"
        sync_root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        try:
            (sync_root / "link").symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available on this platform")

        use_case, metadata = _receiver(sync_root, [_push("link/evil.txt", b"pwned")])
        await use_case.run_forever()

        assert not (outside / "evil.txt").exists(), "peer escaped the sync root via a symlink"
        assert metadata.saved == []

    async def test_malformed_path_does_not_kill_the_receiver(self, tmp_path: Path) -> None:
        """A NUL byte must be a rejected message, not a dead receiver.

        ``open()`` raises ``ValueError`` for an embedded NUL. That
        exception used to escape `run_forever`, ending the background
        task for good — one malformed packet from any peer would stop
        this device receiving anything, from anyone, until restart.
        """
        sync_root = tmp_path / "sync"
        sync_root.mkdir()

        use_case, _ = _receiver(
            sync_root,
            [
                _push("bad\x00name.txt", b"pwned"),
                _push("ok.txt", b"fine"),
            ],
        )
        await use_case.run_forever()

        assert (
            sync_root / "ok.txt"
        ).read_bytes() == b"fine", "receiver stopped processing after one malformed path"


class TestPushPathValidationIsNotOverzealous:
    """The fix must reject attacks without rejecting ordinary sync."""

    async def test_nested_relative_path_is_still_accepted(self, tmp_path: Path) -> None:
        sync_root = tmp_path / "sync"
        sync_root.mkdir()

        use_case, metadata = _receiver(sync_root, [_push("sub/dir/ok.txt", b"fine")])
        await use_case.run_forever()

        assert (sync_root / "sub" / "dir" / "ok.txt").read_bytes() == b"fine"
        assert [m.file_path for m in metadata.saved] == ["sub/dir/ok.txt"]
