"""Unit tests for Conflict Resolution domain entities."""

from securesync.domain.conflict import VersionVector


def test_version_vector_increment() -> None:
    v1 = VersionVector()
    v2 = v1.increment("dev-1")
    assert v2.counters == {"dev-1": 1}

    v3 = v2.increment("dev-1")
    assert v3.counters == {"dev-1": 2}


def test_version_vector_comparison() -> None:
    v1 = VersionVector({"a": 1, "b": 1})
    v2 = VersionVector({"a": 2, "b": 1})
    v3 = VersionVector({"a": 1, "b": 2})

    assert v1 < v2
    assert v1 <= v2
    assert not (v2 <= v1)

    # Concurrent vectors
    assert not (v2 <= v3)
    assert not (v3 <= v2)
    assert v2.is_concurrent(v3)


def test_version_vector_merge() -> None:
    v1 = VersionVector({"a": 1, "b": 5})
    v2 = VersionVector({"a": 3, "b": 2, "c": 1})

    merged = v1.merge(v2)
    assert merged.counters == {"a": 3, "b": 5, "c": 1}
