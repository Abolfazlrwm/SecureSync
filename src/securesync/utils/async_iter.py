"""Generic helper for driving a blocking iterator without blocking the event loop.

Used by the chunk engine's use cases to consume synchronous, generator-
based domain/infrastructure code (chosen deliberately for local,
blocking file I/O — see ADR-0008) from ``async`` application code. Kept
here rather than in ``application/`` because it's stateless, generic,
and has no dependency on the chunk engine specifically — any future
phase (Delta Sync, Transfer Engine) that wraps its own blocking
iteration in an async use case can reuse it as-is.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable, Iterator
from typing import cast

_SENTINEL: object = object()


async def iter_in_thread[T](sync_iterable: Iterable[T]) -> AsyncIterator[T]:
    """Bridge a blocking iterator into an async iterator via a worker thread.

    Each underlying ``next()`` call runs in a worker thread
    (:func:`asyncio.to_thread`), so the event loop is never blocked
    waiting on disk I/O or CPU-bound work — but items still cross back
    to the caller one at a time, so memory stays bounded by a single
    item, never the whole sequence.

    Args:
        sync_iterable: Any blocking iterable (typically a generator)
            whose ``__next__`` performs blocking work.

    Yields:
        Each item of ``sync_iterable``, in order.
    """
    iterator: Iterator[T] = iter(sync_iterable)
    while True:
        result = await asyncio.to_thread(next, iterator, _SENTINEL)
        if result is _SENTINEL:
            return
        yield cast(T, result)
