"""Per-session key material and lifecycle policy for the v2 wire protocol.

The v1 :class:`~securesync.infrastructure.networking.session_key_store.SessionKeyStore`
maps one ``device_id`` to one ``PeerSession``: a second handshake with the same
peer overwrites the first, and receive-side lookups have to trial-decrypt
against every known key because the frame carries no session identifier.

This module is the v2 replacement (Step 1d):

* sessions are keyed by ``session_id`` as the **primary** key, so the receiver
  resolves a frame in O(1) and never trial-decrypts;
* a secondary index ``peer_id -> [session_id]`` supports send-side selection;
* several sessions may exist **concurrently** for the same peer, which is what
  makes reconnects after a restart safe — a new handshake adds a session
  instead of replacing a healthy one;
* per-peer / per-unconfirmed / global caps bound the state an attacker can make
  us hold, with oldest-created-first eviction of *unconfirmed* sessions;
* idle timeouts and an absolute key lifetime bound how long a compromised key
  stays usable;
* :meth:`SessionStore.remove_by_peer` supports item 1f, where untrusting a peer
  must drop **every** session belonging to it.

Per-source-IP handshake rate limiting deliberately does **not** live here: the
store has no notion of a source address, and the limit has to be applied at the
handshake server *before* the expensive X25519/Ed25519 work. It lives in
:mod:`securesync.infrastructure.networking.handshake_rate_limit` instead.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from securesync.infrastructure.networking.replay_protection import (
    SESSION_ID_SIZE,
    AntiReplayWindow,
)

# --- Caps and lifetimes --------------------------------------------------------

#: Maximum concurrent sessions a single peer may hold.
MAX_SESSIONS_PER_PEER = 8
#: Maximum *unconfirmed* sessions a single peer may hold. Kept well below
#: :data:`MAX_SESSIONS_PER_PEER` so a flood of replayed hellos evicts only other
#: unconfirmed sessions and can never displace a confirmed one.
MAX_UNCONFIRMED_PER_PEER = 4
#: Hard cap on total sessions across all peers.
GLOBAL_SESSION_CAP = 256
#: Absolute lifetime of a session's keys, regardless of activity.
MAX_KEY_LIFETIME_S = 24 * 3600.0
#: Idle timeout for a confirmed session.
IDLE_TIMEOUT_CONFIRMED_S = 3600.0
#: Idle timeout for an unconfirmed session (short: it is wasted state).
IDLE_TIMEOUT_UNCONFIRMED_S = 60.0
#: Maximum messages a single key may encrypt before it must be replaced.
MAX_MESSAGES_PER_KEY = 2**32
#: Maximum AEAD counter value (8-byte big-endian nonce field).
MAX_COUNTER = 2**63 - 1


class SessionStoreError(Exception):
    """Base class for session-store failures."""


class CounterExhaustedError(SessionStoreError):
    """A session's send counter or key usage limit is exhausted.

    Callers must open a **new session** in response; this is never a dead end.
    """


class NoSessionError(SessionStoreError):
    """No usable session exists for a peer, so a new handshake is required."""


@dataclass(slots=True)
class PeerSession:
    """One negotiated session with one peer.

    Attributes:
        peer_id: The peer's device ID.
        session_id: The 8-byte session identifier carried in the wire frame.
        role: :data:`~securesync.infrastructure.networking.replay_protection.ROLE_INITIATOR`
            or ``ROLE_RESPONDER`` for this device.
        send_key: Key used to encrypt messages sent to ``peer_id``.
        receive_key: Key used to decrypt messages received from ``peer_id``.
        transfer_port: The peer's chunk-transfer port.
        manifest_port: The peer's manifest-exchange port.
        confirmed: Whether this session is confirmed (role-dependent; see the
            module docstring of the design document).
        created_at: Epoch seconds when the session was created.
        last_activity: Epoch seconds of the last send or receive.
        next_send_counter: The next AEAD counter to allocate (starts at 1).
        sent_count: How many messages this session's send key has encrypted.
        receive_window: Per-session anti-replay window for inbound counters.
    """

    peer_id: str
    session_id: bytes
    role: int
    send_key: bytes
    receive_key: bytes
    transfer_port: int
    manifest_port: int
    confirmed: bool = False
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    next_send_counter: int = 1
    sent_count: int = 0
    receive_window: AntiReplayWindow = field(default_factory=AntiReplayWindow)

    def mark_active(self, now: float | None = None) -> None:
        """Record activity at ``now`` (defaults to the current time)."""
        self.last_activity = now if now is not None else time.time()

    def allocate_counter(self) -> int:
        """Return the next send counter and advance the session's counter.

        The read and the increment happen with no ``await`` between them, so two
        coroutines can never be handed the same counter (which would reuse an
        AEAD nonce under the same key).

        Returns:
            The counter to use as both the frame nonce counter and the inner
            packet's ``message_id``.

        Raises:
            CounterExhaustedError: If the key has hit
                :data:`MAX_MESSAGES_PER_KEY` or the counter would exceed
                :data:`MAX_COUNTER`. The caller must open a new session.
        """
        if self.sent_count >= MAX_MESSAGES_PER_KEY or self.next_send_counter > MAX_COUNTER:
            raise CounterExhaustedError(
                f"session {self.session_id.hex()} exhausted its send counter "
                f"({self.sent_count} messages)"
            )
        counter = self.next_send_counter
        self.next_send_counter += 1
        self.sent_count += 1
        return counter

    def can_send(self, now: float, *, max_lifetime_s: float) -> bool:
        """Whether this session may currently be used to send."""
        if not self.confirmed:
            return False
        if now - self.created_at > max_lifetime_s:
            return False
        return not (self.sent_count >= MAX_MESSAGES_PER_KEY or self.next_send_counter > MAX_COUNTER)


class SessionStore:
    """An in-memory ``session_id -> PeerSession`` registry with Step 1d policy."""

    def __init__(
        self,
        now: Callable[[], float] = time.time,
        *,
        max_sessions_per_peer: int = MAX_SESSIONS_PER_PEER,
        max_unconfirmed_per_peer: int = MAX_UNCONFIRMED_PER_PEER,
        global_session_cap: int = GLOBAL_SESSION_CAP,
        max_key_lifetime_s: float = MAX_KEY_LIFETIME_S,
        idle_timeout_confirmed_s: float = IDLE_TIMEOUT_CONFIRMED_S,
        idle_timeout_unconfirmed_s: float = IDLE_TIMEOUT_UNCONFIRMED_S,
    ) -> None:
        """Initialize an empty store.

        Args:
            now: Clock used for timestamps and expiry. Injectable for tests.
            max_sessions_per_peer: Maximum concurrent sessions per peer.
            max_unconfirmed_per_peer: Maximum unconfirmed sessions per peer.
            global_session_cap: Hard cap on total sessions.
            max_key_lifetime_s: Absolute lifetime of a session's keys.
            idle_timeout_confirmed_s: Idle timeout for confirmed sessions.
            idle_timeout_unconfirmed_s: Idle timeout for unconfirmed sessions.
        """
        self._now = now
        self.max_sessions_per_peer = max_sessions_per_peer
        self.max_unconfirmed_per_peer = max_unconfirmed_per_peer
        self.global_session_cap = global_session_cap
        self.max_key_lifetime_s = max_key_lifetime_s
        self.idle_timeout_confirmed_s = idle_timeout_confirmed_s
        self.idle_timeout_unconfirmed_s = idle_timeout_unconfirmed_s
        self._by_session_id: dict[bytes, PeerSession] = {}
        self._by_peer: dict[str, list[bytes]] = {}

    # --- recording ---------------------------------------------------------

    def put(self, session: PeerSession) -> None:
        """Record a negotiated session, evicting only what policy allows.

        Re-recording the same ``session_id`` is an idempotent replace. A new
        session never replaces a *different* existing session for the same peer:
        at most it triggers eviction of the oldest unconfirmed session, and only
        once the per-peer or global cap is reached.

        Args:
            session: The session to record.

        Raises:
            SessionStoreError: If ``session.session_id`` is the wrong length.
        """
        if len(session.session_id) != SESSION_ID_SIZE:
            raise SessionStoreError(
                f"session_id must be {SESSION_ID_SIZE} bytes, got {len(session.session_id)}"
            )
        if session.session_id in self._by_session_id:
            self._by_session_id[session.session_id] = session
            self._index_peer(session.peer_id, session.session_id)
            return

        self.prune_expired()
        self._enforce_peer_caps(session.peer_id)
        self._enforce_global_cap()

        self._by_session_id[session.session_id] = session
        self._index_peer(session.peer_id, session.session_id)

    def _index_peer(self, peer_id: str, session_id: bytes) -> None:
        ids = self._by_peer.setdefault(peer_id, [])
        if session_id not in ids:
            ids.append(session_id)

    def _enforce_peer_caps(self, peer_id: str) -> None:
        ids = self._by_peer.get(peer_id, [])
        unconfirmed = [sid for sid in ids if not self._by_session_id[sid].confirmed]
        while len(unconfirmed) >= self.max_unconfirmed_per_peer:
            if not self._evict_oldest_created(unconfirmed):
                break
            unconfirmed = [
                sid
                for sid in self._by_peer.get(peer_id, [])
                if not self._by_session_id[sid].confirmed
            ]
        while len(self._by_peer.get(peer_id, [])) >= self.max_sessions_per_peer:
            ids = self._by_peer.get(peer_id, [])
            if self._evict_oldest_created(ids):
                continue
            if self._evict_lru_confirmed(ids):
                continue
            break

    def _enforce_global_cap(self) -> None:
        while len(self._by_session_id) >= self.global_session_cap:
            all_ids = list(self._by_session_id)
            if self._evict_oldest_created(all_ids):
                continue
            if self._evict_lru_confirmed(all_ids):
                continue
            raise SessionStoreError(
                f"global session cap ({self.global_session_cap}) reached and no session to evict"
            )

    def _evict_oldest_created(self, candidate_ids: list[bytes]) -> bool:
        """Evict the oldest-created **unconfirmed** session among the candidates."""
        oldest: bytes | None = None
        oldest_time = float("inf")
        for sid in candidate_ids:
            sess = self._by_session_id.get(sid)
            if sess is None or sess.confirmed:
                continue
            if sess.created_at < oldest_time:
                oldest, oldest_time = sid, sess.created_at
        if oldest is None:
            return False
        self._remove(oldest)
        return True

    def _evict_lru_confirmed(self, candidate_ids: list[bytes]) -> bool:
        """Evict the least-recently-used **confirmed** session among the candidates."""
        lru: bytes | None = None
        lru_activity = float("inf")
        for sid in candidate_ids:
            sess = self._by_session_id.get(sid)
            if sess is None or not sess.confirmed:
                continue
            if sess.last_activity < lru_activity:
                lru, lru_activity = sid, sess.last_activity
        if lru is None:
            return False
        self._remove(lru)
        return True

    def _remove(self, session_id: bytes) -> None:
        sess = self._by_session_id.pop(session_id, None)
        if sess is None:
            return
        ids = self._by_peer.get(sess.peer_id)
        if ids is not None:
            ids[:] = [sid for sid in ids if sid != session_id]
            if not ids:
                self._by_peer.pop(sess.peer_id, None)

    # --- lookup ------------------------------------------------------------

    def get_by_session_id(self, session_id: bytes) -> PeerSession | None:
        """Return the session for ``session_id`` in O(1), or ``None``."""
        return self._by_session_id.get(session_id)

    def sessions_for_peer(self, peer_id: str) -> list[PeerSession]:
        """Return every live session recorded for ``peer_id``."""
        ids = self._by_peer.get(peer_id, [])
        return [self._by_session_id[sid] for sid in ids if sid in self._by_session_id]

    def get_active_session(self, peer_id: str) -> PeerSession | None:
        """Return any live session for ``peer_id``, preferring the most recent."""
        sessions = self.sessions_for_peer(peer_id)
        if not sessions:
            return None
        return max(sessions, key=lambda s: s.last_activity)

    def get_send_session(self, peer_id: str) -> PeerSession | None:
        """Return the best session for *sending* to ``peer_id``, or ``None``.

        A session is usable only if it is confirmed, not past its key lifetime
        and not counter-exhausted. ``None`` means the caller must open a new
        handshake.
        """
        now = self._now()
        candidates = [
            s
            for s in self.sessions_for_peer(peer_id)
            if s.can_send(now, max_lifetime_s=self.max_key_lifetime_s)
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda s: s.last_activity)

    def confirm(self, session_id: bytes) -> None:
        """Mark a session confirmed (idempotent)."""
        sess = self._by_session_id.get(session_id)
        if sess is not None:
            sess.confirmed = True

    def has_confirmed_session(self, peer_id: str) -> bool:
        """Whether ``peer_id`` currently has at least one confirmed session."""
        return any(s.confirmed for s in self.sessions_for_peer(peer_id))

    # --- maintenance -------------------------------------------------------

    def remove_by_peer(self, peer_id: str) -> int:
        """Purge **every** session for ``peer_id``.

        Used when a peer is untrusted (item 1f): a single surviving session would
        keep that peer authenticated.

        Returns:
            The number of sessions removed.
        """
        ids = list(self._by_peer.get(peer_id, []))
        for sid in ids:
            self._remove(sid)
        return len(ids)

    def prune_expired(self) -> int:
        """Remove sessions past their key lifetime or idle timeout.

        Returns:
            The number of sessions removed.
        """
        now = self._now()
        expired = [sid for sid, sess in self._by_session_id.items() if self._is_expired(sess, now)]
        for sid in expired:
            self._remove(sid)
        return len(expired)

    def _is_expired(self, session: PeerSession, now: float) -> bool:
        if now - session.created_at > self.max_key_lifetime_s:
            return True
        idle_limit = (
            self.idle_timeout_confirmed_s if session.confirmed else self.idle_timeout_unconfirmed_s
        )
        return now - session.last_activity > idle_limit

    def __len__(self) -> int:
        """Return the number of recorded sessions."""
        return len(self._by_session_id)

    def all_sessions(self) -> list[PeerSession]:
        """Return every recorded session (diagnostics)."""
        return list(self._by_session_id.values())
