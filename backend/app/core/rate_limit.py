"""In-process sliding-window rate limiting for sensitive endpoints.

Used by the login endpoint to slow down online credential guessing. The
semantics are deliberately conservative and simple:

* Only *failed* attempts count toward the limit; a successful sign-in
  clears the failure history for its key and is never throttled.
* The limiter stores timestamps and the *count* of failures — never
  passwords, tokens, or any payload content.
* When the limit is reached the caller is rejected with ``429`` and a
  ``Retry-After`` header until the oldest failure leaves the window.

Scope and limitations (documented, not hidden):

* State is **per-process and in-memory**. With multiple workers or
  replicas the effective fleet-wide limit multiplies by the number of
  processes; a shared store (e.g. Redis) would be required for a global
  quota. This is a mitigation layer, not a distributed quota.
* Keys combine the submitted username with the peer address, so one
  attacker cannot lock out a victim signing in from elsewhere, and one
  bad password does not throttle unrelated accounts.

The implementation is pure Python (dict + deque + lock) with no I/O, so
its own failure modes are limited to process death.
"""

from __future__ import annotations

import math
import time
from collections import deque
from threading import Lock
from typing import Callable


class SlidingWindowRateLimiter:
    """Tracks recent failures per key and reports when a key is limited."""

    def __init__(
        self,
        *,
        max_failures: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_failures < 1:
            raise ValueError("max_failures must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self.max_failures = int(max_failures)
        self.window_seconds = float(window_seconds)
        self._clock = clock
        self._failures: dict[str, deque[float]] = {}
        self._lock = Lock()

    # ── internals ───────────────────────────────────────────────────

    def _prune(self, key: str, now: float) -> deque[float]:
        """Return ``key``'s live failures, dropping entries out of window."""
        bucket = self._failures.get(key)
        if bucket is None:
            return deque()
        cutoff = now - self.window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if not bucket:
            # Keep the dict from growing with stale keys.
            self._failures.pop(key, None)
        return bucket

    # ── public API ──────────────────────────────────────────────────

    def record_failure(self, key: str) -> None:
        """Register one failed attempt for ``key``."""
        now = self._clock()
        with self._lock:
            bucket = self._prune(key, now)
            bucket.append(now)
            self._failures[key] = bucket

    def retry_after(self, key: str) -> float | None:
        """Seconds until ``key`` may retry, or ``None`` when not limited."""
        now = self._clock()
        with self._lock:
            bucket = self._prune(key, now)
            if len(bucket) < self.max_failures:
                return None
            # The oldest failure must age out of the window first.
            return max(self.window_seconds - (now - bucket[0]), 0.0)

    def clear(self, key: str) -> None:
        """Forget failures for ``key`` (used after a successful sign-in)."""
        with self._lock:
            self._failures.pop(key, None)

    def reset(self) -> None:
        """Drop all state — for tests and administrative resets."""
        with self._lock:
            self._failures.clear()


def retry_after_header_seconds(seconds: float) -> int:
    """Round ``Retry-After`` up so clients never retry early."""
    return max(1, int(math.ceil(seconds)))


#: Process-wide limiters guarding the login endpoint. Tests that need
#: different thresholds should substitute these references (monkeypatch)
#: rather than mutating them.
from app.core.config import settings as _settings  # noqa: E402  (avoid config cycle)

#: Per (username, address): a single account+client cannot guess forever.
login_rate_limiter = SlidingWindowRateLimiter(
    max_failures=_settings.AUTH_RATE_LIMIT_MAX_FAILURES,
    window_seconds=_settings.AUTH_RATE_LIMIT_WINDOW_SECONDS,
)

#: Per address: rotating usernames from one client cannot dodge the limit.
login_ip_rate_limiter = SlidingWindowRateLimiter(
    max_failures=_settings.AUTH_RATE_LIMIT_IP_MAX_FAILURES,
    window_seconds=_settings.AUTH_RATE_LIMIT_WINDOW_SECONDS,
)
