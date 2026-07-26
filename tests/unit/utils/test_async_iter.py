"""Unit tests for `securesync.utils.async_iter.iter_in_thread`."""

from __future__ import annotations

import threading
from collections.abc import Iterator

import pytest

from securesync.utils.async_iter import iter_in_thread


def _range_generator(n: int) -> Iterator[int]:
    yield from range(n)


class TestIterInThread:
    """Tests for `iter_in_thread`."""

    async def test_yields_every_item_in_order(self) -> None:
        """Items are yielded in the same order the source iterable produces them."""
        results = [item async for item in iter_in_thread(_range_generator(5))]
        assert results == [0, 1, 2, 3, 4]

    async def test_empty_iterable_yields_nothing(self) -> None:
        """An empty source iterable produces an empty async iteration."""
        results = [item async for item in iter_in_thread(_range_generator(0))]
        assert results == []

    async def test_works_with_a_plain_list(self) -> None:
        """Any iterable works, not only generators."""
        results = [item async for item in iter_in_thread([1, 2, 3])]
        assert results == [1, 2, 3]

    async def test_exception_from_source_propagates(self) -> None:
        """An exception raised mid-iteration by the source propagates to the caller."""

        def _failing() -> Iterator[int]:
            yield 1
            raise RuntimeError("boom")

        results = []
        with pytest.raises(RuntimeError, match="boom"):
            async for item in iter_in_thread(_failing()):
                results.append(item)
        assert results == [1]

    async def test_iteration_runs_off_the_calling_thread(self) -> None:
        """`next()` calls happen in a worker thread, not the caller's thread."""
        caller_thread = threading.current_thread()
        worker_threads = set()

        def _record_thread() -> Iterator[int]:
            for i in range(3):
                worker_threads.add(threading.current_thread())
                yield i

        _ = [item async for item in iter_in_thread(_record_thread())]

        assert caller_thread not in worker_threads
