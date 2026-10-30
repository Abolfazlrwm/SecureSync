"""Tests for per-source-IP handshake rate limiting (Step 1d DoS defense)."""

from __future__ import annotations

import pytest

from securesync.infrastructure.networking.handshake_rate_limit import (
    MAX_HANDSHAKES_PER_IP,
    SourceIpRateLimiter,
)
from securesync.infrastructure.networking.x25519_handshake import HandshakeServer


class TestSourceIpRateLimiter:
    def test_allows_up_to_the_limit_then_denies(self) -> None:
        limiter = SourceIpRateLimiter(max_attempts=3, window_s=60.0, now=lambda: 1000.0)
        assert [limiter.allow("1.2.3.4") for _ in range(3)] == [True, True, True]
        assert limiter.allow("1.2.3.4") is False

    def test_different_sources_have_independent_budgets(self) -> None:
        limiter = SourceIpRateLimiter(max_attempts=1, window_s=60.0, now=lambda: 1000.0)
        assert limiter.allow("1.2.3.4") is True
        assert limiter.allow("1.2.3.4") is False
        assert limiter.allow("5.6.7.8") is True

    def test_budget_recovers_after_the_window(self) -> None:
        clock = {"now": 1000.0}
        limiter = SourceIpRateLimiter(max_attempts=1, window_s=10.0, now=lambda: clock["now"])
        assert limiter.allow("1.2.3.4") is True
        assert limiter.allow("1.2.3.4") is False
        clock["now"] += 11.0
        assert limiter.allow("1.2.3.4") is True

    def test_denied_attempts_do_not_extend_the_window(self) -> None:
        clock = {"now": 1000.0}
        limiter = SourceIpRateLimiter(max_attempts=1, window_s=10.0, now=lambda: clock["now"])
        assert limiter.allow("1.2.3.4") is True
        clock["now"] += 5.0
        assert limiter.allow("1.2.3.4") is False
        clock["now"] += 6.0
        assert limiter.allow("1.2.3.4") is True

    def test_default_limit_is_thirty_per_minute(self) -> None:
        limiter = SourceIpRateLimiter(now=lambda: 1000.0)
        assert all(limiter.allow("9.9.9.9") for _ in range(MAX_HANDSHAKES_PER_IP))
        assert limiter.allow("9.9.9.9") is False

    def test_rejects_non_positive_configuration(self) -> None:
        with pytest.raises(ValueError):
            SourceIpRateLimiter(max_attempts=0)
        with pytest.raises(ValueError):
            SourceIpRateLimiter(window_s=0.0)

    def test_prune_drops_stale_sources(self) -> None:
        clock = {"now": 1000.0}
        limiter = SourceIpRateLimiter(max_attempts=2, window_s=10.0, now=lambda: clock["now"])
        limiter.allow("1.2.3.4")
        clock["now"] += 11.0
        assert limiter.prune() == 1
        assert limiter.prune() == 0

    def test_reset_forgets_one_source(self) -> None:
        limiter = SourceIpRateLimiter(max_attempts=1, window_s=60.0, now=lambda: 1000.0)
        limiter.allow("1.2.3.4")
        assert limiter.allow("1.2.3.4") is False
        limiter.reset("1.2.3.4")
        assert limiter.allow("1.2.3.4") is True


class _FakeWriter:
    """Minimal writer double exposing only what the server touches."""

    def __init__(self, peer_ip: str | None) -> None:
        self._peer_ip = peer_ip
        self.closed = False

    def get_extra_info(self, name: str) -> object:
        if name == "peername" and self._peer_ip is not None:
            return (self._peer_ip, 55555)
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class _CountingHandshake:
    """Handshake double that records how often the expensive path was entered."""

    def __init__(self) -> None:
        self.accept_calls = 0

    async def accept(self, reader: object, writer: object) -> object:
        self.accept_calls += 1
        return object()


class TestHandshakeServerEnforcesTheLimitBeforeCrypto:
    async def test_second_handshake_from_same_ip_is_refused_before_accept(self) -> None:
        limiter = SourceIpRateLimiter(max_attempts=1, window_s=60.0, now=lambda: 1000.0)
        handshake = _CountingHandshake()
        server = HandshakeServer(handshake, rate_limiter=limiter)  # type: ignore[arg-type]

        first = _FakeWriter("1.2.3.4")
        await server._handle_connection(object(), first)  # type: ignore[arg-type]
        assert first.closed is True
        assert handshake.accept_calls == 1

        second = _FakeWriter("1.2.3.4")
        await server._handle_connection(object(), second)  # type: ignore[arg-type]
        assert second.closed is True
        # The limiter stopped it before `accept` — no second X25519/Ed25519.
        assert handshake.accept_calls == 1

    async def test_a_different_ip_is_still_admitted(self) -> None:
        limiter = SourceIpRateLimiter(max_attempts=1, window_s=60.0, now=lambda: 1000.0)
        handshake = _CountingHandshake()
        server = HandshakeServer(handshake, rate_limiter=limiter)  # type: ignore[arg-type]

        await server._handle_connection(object(), _FakeWriter("1.2.3.4"))  # type: ignore[arg-type]
        await server._handle_connection(object(), _FakeWriter("5.6.7.8"))  # type: ignore[arg-type]
        assert handshake.accept_calls == 2
