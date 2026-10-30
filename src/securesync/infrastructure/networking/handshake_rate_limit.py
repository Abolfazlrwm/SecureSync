"""Per-source-IP rate limiting for inbound handshakes.

Every inbound handshake costs the responder an X25519 keypair, an ECDH, an
Ed25519 verify and a trust-store read before the peer has proven anything. A
single host can otherwise make us burn that work at line rate, so the limit is
applied at :class:`~securesync.infrastructure.networking.x25519_handshake.HandshakeServer`
*before* :meth:`X25519Handshake.accept` runs — i.e. before any curve arithmetic.

The limiter is keyed by the hello's **source IP** (the TCP peer address), not by
the device ID inside the message: that field is unauthenticated at this point
and would let an attacker dodge the limit by inventing new IDs.
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
