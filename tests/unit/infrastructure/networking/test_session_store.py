"""Unit tests for the v2 session store (session_id keying, caps, expiry, counters)."""

from __future__ import annotations

import pytest

from securesync.infrastructure.networking.replay_protection import (
    ROLE_INITIATOR,
    ROLE_RESPONDER,
)
from securesync.infrastructure.networking.session_store import (
    CounterExhaustedError,
    PeerSession,
    SessionStore,
    SessionStoreError,
)

NOW = 1000.0


def _sid(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _session(
    peer_id: str,
    session_id: bytes,
    *,
    role: int = ROLE_INITIATOR,
    confirmed: bool = False,
    created_at: float = NOW,
    last_activity: float = NOW,
) -> PeerSession:
    return PeerSession(
        peer_id=peer_id,
        session_id=session_id,
        role=role,
        send_key=b"s" * 32,
        receive_key=b"r" * 32,
        transfer_port=9000,
        manifest_port=9001,
        confirmed=confirmed,
        created_at=created_at,
        last_activity=last_activity,
    )


def _store(**kwargs: float) -> SessionStore:
    return SessionStore(now=lambda: NOW, **kwargs)  # type: ignore[arg-type]


class TestKeyingAndLookup:
    def test_put_then_get_by_session_id(self) -> None:
        store = _store()
        store.put(_session("peer-a", _sid(1)))
        found = store.get_by_session_id(_sid(1))
        assert found is not None
        assert found.peer_id == "peer-a"

    def test_unknown_session_id_returns_none(self) -> None:
        assert _store().get_by_session_id(_sid(99)) is None

    def test_invalid_session_id_length_rejected(self) -> None:
        with pytest.raises(SessionStoreError):
            _store().put(_session("p", b"short"))

    def test_multiple_sessions_for_one_peer_coexist(self) -> None:
        store = _store()
        store.put(_session("p", _sid(1)))
        store.put(_session("p", _sid(2)))
        assert len(store) == 2
        assert {s.session_id for s in store.sessions_for_peer("p")} == {_sid(1), _sid(2)}

    def test_put_same_session_id_is_idempotent(self) -> None:
        store = _store()
        store.put(_session("p", _sid(1)))
        store.put(_session("p", _sid(1), confirmed=True))
        assert len(store) == 1
        assert store.get_by_session_id(_sid(1)).confirmed is True  # type: ignore[union-attr]


class TestSendSessionSelection:
    def test_unconfirmed_session_is_not_usable_for_sending(self) -> None:
        store = _store()
        store.put(_session("p", _sid(1), confirmed=False))
        assert store.get_send_session("p") is None

    def test_confirmed_session_is_usable(self) -> None:
        store = _store()
        store.put(_session("p", _sid(1), confirmed=True))
        assert store.get_send_session("p") is not None

    def test_prefers_most_recently_active_confirmed(self) -> None:
        store = _store()
        store.put(_session("p", _sid(1), confirmed=True, last_activity=NOW - 10))
        store.put(_session("p", _sid(2), confirmed=True, last_activity=NOW))
        chosen = store.get_send_session("p")
        assert chosen is not None
        assert chosen.session_id == _sid(2)

    def test_expired_key_is_not_usable_for_sending(self) -> None:
        store = _store()
        store.put(_session("p", _sid(1), confirmed=True, created_at=NOW - (24 * 3600) - 1))
        assert store.get_send_session("p") is None

    def test_unknown_peer_has_no_send_session(self) -> None:
        assert _store().get_send_session("nope") is None


class TestCapsAndEviction:
    def test_unconfirmed_cap_evicts_oldest_created(self) -> None:
        store = _store()
        for i in range(4):
            store.put(_session("p", _sid(i), created_at=NOW - 100 + i))
        store.put(_session("p", _sid(9), created_at=NOW))
        assert store.get_by_session_id(_sid(0)) is None
        assert store.get_by_session_id(_sid(9)) is not None

    def test_replayed_hello_never_evicts_a_confirmed_session(self) -> None:
        store = _store()
        store.put(_session("p", _sid(0), confirmed=True, created_at=NOW - 500))
        for i in range(1, 5):
            store.put(_session("p", _sid(i), created_at=NOW - 100 + i))
        store.put(_session("p", _sid(9), created_at=NOW))
        assert store.get_by_session_id(_sid(0)) is not None
        assert store.get_by_session_id(_sid(9)) is not None

    def test_per_peer_cap_evicts_lru_confirmed_when_all_are_confirmed(self) -> None:
        store = _store()
        for i in range(8):
            store.put(
                _session(
                    "p",
                    _sid(i),
                    confirmed=True,
                    created_at=NOW - 100 + i,
                    last_activity=NOW - 100 + i,
                )
            )
        store.put(_session("p", _sid(9), created_at=NOW))
        assert len(store) == 8
        assert store.get_by_session_id(_sid(0)) is None
        assert store.get_by_session_id(_sid(9)) is not None

    def test_global_cap_evicts_oldest_unconfirmed(self) -> None:
        store = _store(global_session_cap=3)
        for i in range(3):
            store.put(_session(f"peer-{i}", _sid(i), created_at=NOW - 10 + i))
        store.put(_session("peer-new", _sid(9), created_at=NOW))
        assert len(store) == 3
        assert store.get_by_session_id(_sid(0)) is None
        assert store.get_by_session_id(_sid(9)) is not None


class TestExpiry:
    def test_max_key_lifetime(self) -> None:
        store = _store()
        store.put(_session("p", _sid(1), created_at=NOW - (24 * 3600) - 1))
        assert store.prune_expired() == 1
        assert store.get_by_session_id(_sid(1)) is None

    def test_unconfirmed_idle_timeout(self) -> None:
        store = _store()
        store.put(_session("p", _sid(1), created_at=NOW - 10, last_activity=NOW - 61))
        assert store.prune_expired() == 1

    def test_confirmed_session_uses_the_longer_idle_timeout(self) -> None:
        store = _store()
        store.put(
            _session("p", _sid(1), confirmed=True, created_at=NOW - 10, last_activity=NOW - 61)
        )
        assert store.prune_expired() == 0

    def test_confirmed_idle_timeout_eventually_expires(self) -> None:
        store = _store()
        store.put(
            _session("p", _sid(1), confirmed=True, created_at=NOW - 10, last_activity=NOW - 3601)
        )
        assert store.prune_expired() == 1


class TestCounters:
    def test_counter_starts_at_one_and_increments(self) -> None:
        session = _session("p", _sid(1))
        assert session.allocate_counter() == 1
        assert session.allocate_counter() == 2
        assert session.allocate_counter() == 3

    def test_counter_exhaustion_raises(self) -> None:
        session = _session("p", _sid(1))
        session.next_send_counter = 2**63
        with pytest.raises(CounterExhaustedError):
            session.allocate_counter()

    def test_message_count_exhaustion_raises(self) -> None:
        session = _session("p", _sid(1))
        session.sent_count = 2**32
        with pytest.raises(CounterExhaustedError):
            session.allocate_counter()


class TestUntrustPurge:
    def test_remove_by_peer_purges_every_session(self) -> None:
        store = _store()
        store.put(_session("p", _sid(1)))
        store.put(_session("p", _sid(2), role=ROLE_RESPONDER))
        store.put(_session("other", _sid(3)))
        assert store.remove_by_peer("p") == 2
        assert store.get_by_session_id(_sid(1)) is None
        assert store.get_by_session_id(_sid(3)) is not None

    def test_confirm_marks_session(self) -> None:
        store = _store()
        store.put(_session("p", _sid(1)))
        assert store.has_confirmed_session("p") is False
        store.confirm(_sid(1))
        assert store.has_confirmed_session("p") is True
