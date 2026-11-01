"""Per-source-IP rate limiting for inbound handshakes.

Every inbound handshake costs the responder an X25519 keypair, an ECDH, an
Ed25519 verify and a trust-store read before the peer has proven anything. A
single host can otherwise make us burn that work at line rate, so the limit is
applied at :class:`~securesync.infrastructure.networking.x25519_handshake.HandshakeServer`
*before* :meth:`X25519Handshake.accept` runs — i.e. before any curve arithmetic.

The limiter is keyed by the hello's **source IP** (the TCP peer address), not by
the device ID inside the message: that field is unauthenticated at this point
and would let an attacker dodge the limit by inventing new IDs.

A per-IP limit alone is not enough once an attacker has many addresses, so
:class:`GlobalHandshakeLimiter` adds a process-wide token bucket on top. It is
deliberately coarser: it protects the machine, while the per-IP limit protects
one peer's fair share.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Final

#: Maximum handshake attempts accepted from one source IP per window.
MAX_HANDSHAKES_PER_IP: Final = 30
#: Sliding window length, in seconds.
HANDSHAKE_RATE_WINDOW_S: Final = 60.0
#: Source label used when the transport cannot report a peer address.
UNKNOWN_SOURCE: Final = "unknown"


class SourceIpRateLimiter:
    """A sliding-window rate limiter keyed by source IP address."""

    def __init__(
        self,
        max_attempts: int = MAX_HANDSHAKES_PER_IP,
        window_s: float = HANDSHAKE_RATE_WINDOW_S,
        now: Callable[[], float] = time.time,
    ) -> None:
        """Initialize the limiter.

        Args:
            max_attempts: Attempts allowed per source IP per window.
            window_s: Sliding window length in seconds.
            now: Clock, injectable for tests.

        Raises:
            ValueError: If ``max_attempts`` or ``window_s`` is not positive.
        """
        if max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if window_s <= 0:
            raise ValueError("window_s must be positive")
        self._max = max_attempts
        self._window = window_s
        self._now = now
        self._attempts: dict[str, list[float]] = {}

    def allow(self, source_ip: str) -> bool:
        """Record an attempt from ``source_ip`` and report whether it is allowed.

        A denied attempt is **not** recorded, so a well-behaved peer is not
        pushed further out of the window by an attacker sharing its IP.

        Args:
            source_ip: The connecting host's address.

        Returns:
            ``True`` if the attempt is within the limit, ``False`` otherwise.
        """
        now = self._now()
        cutoff = now - self._window
        times = self._attempts.setdefault(source_ip, [])
        times[:] = [t for t in times if t > cutoff]
        if len(times) >= self._max:
            return False
        times.append(now)
        return True

    def reset(self, source_ip: str | None = None) -> None:
        """Forget recorded attempts for one source, or for every source."""
        if source_ip is None:
            self._attempts.clear()
        else:
            self._attempts.pop(source_ip, None)

    def prune(self) -> int:
        """Drop sources whose attempts have all aged out of the window.

        Returns:
            The number of source entries removed.
        """
        cutoff = self._now() - self._window
        stale = [ip for ip, times in self._attempts.items() if not any(t > cutoff for t in times)]
        for ip in stale:
            del self._attempts[ip]
        return len(stale)


#: Process-wide handshake admission rate, in handshakes per second.
MAX_HANDSHAKES_GLOBAL_PER_S: Final = 200.0
#: How many handshakes may be admitted back-to-back after an idle period.
GLOBAL_HANDSHAKE_BURST: Final = 400.0


class GlobalHandshakeLimiter:
    """A token bucket capping handshakes per second across the whole process.

    A sliding window would either allow a burst equal to the window size or
    none at all; a token bucket admits a burst after idle time and then settles
    at the sustained rate, which is what "200/s with a burst of 400" means.
    """

    def __init__(
        self,
        rate_per_s: float = MAX_HANDSHAKES_GLOBAL_PER_S,
        burst: float = GLOBAL_HANDSHAKE_BURST,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize the bucket full.

        Args:
            rate_per_s: Sustained admission rate.
            burst: Bucket capacity, i.e. the largest instantaneous burst.
            now: Monotonic clock, injectable for tests.

        Raises:
            ValueError: If ``rate_per_s`` or ``burst`` is not positive.
        """
        if rate_per_s <= 0:
            raise ValueError("rate_per_s must be positive")
        if burst <= 0:
            raise ValueError("burst must be positive")
        self._rate = rate_per_s
        self._burst = burst
        self._now = now
        self._tokens = burst
        self._last = now()

    @property
    def tokens(self) -> float:
        """Tokens currently available, after refilling."""
        self._refill()
        return self._tokens

    def _refill(self) -> None:
        now = self._now()
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)

    def allow(self) -> bool:
        """Consume one token and report whether the handshake is admitted.

        Returns:
            ``True`` if a token was available, ``False`` if the bucket is empty.
        """
        self._refill()
        if self._tokens < 1.0:
            return False
        self._tokens -= 1.0
        return True
