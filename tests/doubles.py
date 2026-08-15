"""Test doubles shared across the test suite.

Per CONTRIBUTING.md, every port added to ``domain/`` needs at least one
fake adapter in ``tests/`` so application-layer code can be exercised
without any real I/O. ``FakeFileWatcher`` is that fake for
``domain.watcher.FileWatcher``; ``CollectingObserver`` and
``FailingObserver`` are test doubles for
``domain.watcher.FileSystemEventObserver``. ``FakeChunkReader``,
``FakeChunkHasher``, ``FakeChunkWriter``, and ``FakeChunkRepository``
are the equivalents for the ``domain.chunking`` ports.
``FakeIdentityProvider`` and ``FakeTrustedPeerRepository`` are the
equivalents for ``domain.identity``'s ports.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable, Iterator
from pathlib import Path

from securesync.domain.chunk import Chunk, ChunkAlgorithm, ChunkCollection, ChunkHash
from securesync.domain.chunking import (
    ChunkHasher,
    ChunkingStrategy,
    ChunkReader,
    ChunkRepository,
    ChunkWriter,
)
from securesync.domain.events import FileSystemEvent
from securesync.domain.identity import IdentityKeyPair, IdentityProvider, TrustedPeerRepository
from securesync.domain.watcher import FileSystemEventObserver, FileWatcher


class FakeFileWatcher(FileWatcher):
    """In-memory fake ``FileWatcher`` for testing application-layer code.

    Records every call made to it and lets a test optionally force
    ``start``/``stop`` to raise, without touching a real filesystem or
    thread.
    """

    def __init__(self) -> None:
        """Initialize the fake with no observers and a stopped state."""
        self.start_calls = 0
        self.stop_calls = 0
        self._observers: list[FileSystemEventObserver] = []
        self._running = False
        self.raise_on_start: Exception | None = None
        self.raise_on_stop: Exception | None = None

    async def start(self) -> None:
        """Record the call and flip to running, unless configured to fail."""
        self.start_calls += 1
        if self.raise_on_start is not None:
            raise self.raise_on_start
        self._running = True

    async def stop(self) -> None:
        """Record the call and flip to stopped, unless configured to fail."""
        self.stop_calls += 1
        if self.raise_on_stop is not None:
            raise self.raise_on_stop
        self._running = False

    def subscribe(self, observer: FileSystemEventObserver) -> None:
        """Register ``observer``, mirroring the real port's contract."""
        if observer not in self._observers:
            self._observers.append(observer)

    def unsubscribe(self, observer: FileSystemEventObserver) -> None:
        """Remove ``observer``, mirroring the real port's contract."""
        if observer in self._observers:
            self._observers.remove(observer)

    @property
    def is_running(self) -> bool:
        """Whether ``start`` has been called without a matching ``stop``."""
        return self._running

    @property
    def observers(self) -> list[FileSystemEventObserver]:
        """A snapshot of currently-subscribed observers."""
        return list(self._observers)

    async def emit(self, event: FileSystemEvent) -> None:
        """Test helper: notify every subscribed observer of ``event``.

        Args:
            event: The event to deliver to all subscribed observers.
        """
        for observer in list(self._observers):
            await observer.on_file_event(event)


class CollectingObserver:
    """Observer test double that records every event it receives."""

    def __init__(self) -> None:
        """Initialize with an empty event log."""
        self.events: list[FileSystemEvent] = []
        self._queue: asyncio.Queue[FileSystemEvent] = asyncio.Queue()

    async def on_file_event(self, event: FileSystemEvent) -> None:
        """Append ``event`` to the log and wake any waiter.

        Args:
            event: The event delivered by the watcher.
        """
        self.events.append(event)
        await self._queue.put(event)

    async def wait_for(self, count: int, timeout_seconds: float = 5.0) -> list[FileSystemEvent]:
        """Block until at least ``count`` events have been collected.

        A single real filesystem operation often produces more than one
        raw notification (e.g. a file write also touches the parent
        directory's mtime), so prefer :meth:`wait_until` with a specific
        predicate when a test cares about *which* events arrived, not
        just how many.

        Args:
            count: The number of events to wait for.
            timeout_seconds: Maximum time, in seconds, to wait.

        Returns:
            A snapshot of the collected events once ``count`` is reached.

        Raises:
            TimeoutError: If ``count`` events aren't collected in time.
        """
        return await self.wait_until(
            lambda events: len(events) >= count, timeout_seconds=timeout_seconds
        )

    async def wait_until(
        self,
        predicate: Callable[[list[FileSystemEvent]], bool],
        timeout_seconds: float = 5.0,
    ) -> list[FileSystemEvent]:
        """Block until the collected events satisfy ``predicate``.

        Args:
            predicate: Called with a snapshot of collected events after
                every new arrival; should return ``True`` once the
                awaited condition is met.
            timeout_seconds: Maximum time, in seconds, to wait.

        Returns:
            A snapshot of the collected events once ``predicate`` holds.

        Raises:
            TimeoutError: If the predicate never becomes true in time.
        """

        async def _wait_until_true() -> None:
            while not predicate(self.events):
                await self._queue.get()

        await asyncio.wait_for(_wait_until_true(), timeout=timeout_seconds)
        return list(self.events)


class FailingObserver:
    """Observer test double that always raises, to test error isolation."""

    def __init__(self) -> None:
        """Initialize with a zeroed call counter."""
        self.call_count = 0

    async def on_file_event(self, event: FileSystemEvent) -> None:
        """Increment the call counter, then always raise.

        Args:
            event: The event delivered by the watcher (unused).

        Raises:
            RuntimeError: Always, to simulate a buggy observer.
        """
        self.call_count += 1
        raise RuntimeError("simulated observer failure")


class FakeChunkReader(ChunkReader):
    """In-memory fake ``ChunkReader`` — yields a pre-configured chunk sequence.

    Records every ``(path, strategy)`` pair it was called with, so a
    test can assert the use case passed along the right arguments
    without touching a real file.
    """

    def __init__(self, chunks: list[Chunk] | None = None) -> None:
        """Initialize the fake.

        Args:
            chunks: The chunks ``read_chunks`` yields, in order. Empty
                by default (simulates an empty file).
        """
        self._chunks = chunks or []
        self.calls: list[tuple[Path, ChunkingStrategy]] = []
        self.raise_on_read: Exception | None = None

    def read_chunks(self, path: Path, strategy: ChunkingStrategy) -> Iterator[Chunk]:
        """Record the call, then yield the configured chunks or raise."""
        self.calls.append((path, strategy))
        if self.raise_on_read is not None:
            raise self.raise_on_read
        yield from self._chunks


class FakeChunkHasher(ChunkHasher):
    """In-memory fake ``ChunkHasher`` — hashes via a configurable function.

    Defaults to real SHA-256 (via
    :class:`~securesync.infrastructure.chunking.sha256_hash_provider.SHA256HashProvider`-
    compatible output) so fake-hashed chunks stay verifiable, but a
    test can swap in ``hash_fn`` to force a specific digest.
    """

    def __init__(self, hash_fn: Callable[[bytes | memoryview], ChunkHash] | None = None) -> None:
        """Initialize the fake.

        Args:
            hash_fn: Called with each chunk's data to produce its
                ``ChunkHash``. Defaults to real SHA-256 hashing.
        """
        self._hash_fn = hash_fn or _default_hash
        self.calls: list[bytes] = []

    def hash(self, data: bytes | memoryview) -> ChunkHash:
        """Record the call, then delegate to the configured hash function."""
        self.calls.append(bytes(data))
        return self._hash_fn(data)


def _default_hash(data: bytes | memoryview) -> ChunkHash:
    """Real SHA-256, used as ``FakeChunkHasher``'s default behavior."""
    return ChunkHash(algorithm=ChunkAlgorithm.SHA256, digest=hashlib.sha256(data).hexdigest())


class FakeChunkWriter(ChunkWriter):
    """In-memory fake ``ChunkWriter`` — records writes instead of touching disk."""

    def __init__(self) -> None:
        """Initialize with no recorded writes."""
        self.written: dict[Path, Chunk] = {}
        self.raise_on_write: Exception | None = None

    def write_chunk(self, destination: Path, chunk: Chunk) -> None:
        """Record the write, unless configured to fail."""
        if self.raise_on_write is not None:
            raise self.raise_on_write
        self.written[destination] = chunk


class FakeChunkRepository(ChunkRepository):
    """In-memory fake ``ChunkRepository`` — a dict keyed by source path."""

    def __init__(self) -> None:
        """Initialize with an empty store."""
        self._store: dict[Path, ChunkCollection] = {}
        self.save_calls = 0
        self.load_calls = 0

    def save(self, collection: ChunkCollection) -> None:
        """Record the collection, keyed by its source path."""
        self.save_calls += 1
        self._store[collection.source_path] = collection

    def load(self, source_path: Path) -> ChunkCollection | None:
        """Return the previously saved collection, if any."""
        self.load_calls += 1
        return self._store.get(source_path)


class FakeIdentityProvider(IdentityProvider):
    """In-memory fake ``IdentityProvider`` — no real Ed25519, no disk I/O.

    Uses the same bytes for both "private" and "public" key (there's
    no real asymmetric cryptography here), so ``sign``/``verify`` can
    be simple deterministic string matching instead of needing a real
    keypair relationship.
    """

    def __init__(self, identity: IdentityKeyPair | None = None) -> None:
        """Initialize with a fixed or default fake identity."""
        self._identity = identity or IdentityKeyPair(
            private_key=b"fake-key", public_key=b"fake-key"
        )

    def load_or_create(self) -> IdentityKeyPair:
        """Return the fixed fake identity."""
        return self._identity

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Return a deterministic marker combining the key and message."""
        return private_key + b":" + message

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify the marker was produced by the same key bytes."""
        return signature == public_key + b":" + message


class FakeTrustedPeerRepository(TrustedPeerRepository):
    """In-memory fake ``TrustedPeerRepository`` — a dict keyed by device ID."""

    def __init__(self) -> None:
        """Initialize with an empty trust store."""
        self._store: dict[str, bytes] = {}

    async def get_trusted_key(self, device_id: str) -> bytes | None:
        """Return the pinned key for `device_id`, if any."""
        return self._store.get(device_id)

    async def trust(self, device_id: str, public_key: bytes) -> None:
        """Pin `public_key` as trusted for `device_id`."""
        self._store[device_id] = public_key
