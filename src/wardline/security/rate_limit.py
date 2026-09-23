import math
import time
from collections.abc import Callable
from typing import Protocol

from wardline.contracts import Clock, SecurityEvent, ServiceName, Severity


class RateLimiter(Protocol):
    def allow(self, key: str, *, cost: int = 1) -> bool:
        """Return True when the caller may proceed."""

    def retry_after(self, key: str) -> int:
        ...


class TokenBucketLimiter:
    """
    Token bucket rate limiter.
    Internal keys 'internal:healthcheck' and 'internal:simulation' have a minimum burst
    to allow local exercises to run without stepping on user limits.
    """

    def __init__(
        self,
        *,
        clock: Clock,
        get_limits: Callable[[], tuple[int, int]],
        time_fn: Callable[[], float] | None = None,
        audit_callback: Callable[[SecurityEvent], None] | None = None,
    ) -> None:
        self._clock = clock
        self._get_limits = get_limits
        self._time_fn = time_fn if time_fn is not None else time.monotonic
        self._audit_callback = audit_callback
        self._buckets: dict[str, tuple[float, float]] = {}

    def _get_burst_for_key(self, key: str, base_burst: int) -> int:
        if key in ("internal:healthcheck", "internal:simulation"):
            # simulation_loopback_max_datagrams = 20, simulation_loopback_max_connections = 8
            # max_health_requests = 30
            return max(base_burst, 30)
        return base_burst

    def allow(self, key: str, *, cost: int = 1) -> bool:
        try:
            rate, burst = self._get_limits()
        except Exception:
            if self._audit_callback:
                self._audit_callback(
                    SecurityEvent(
                        timestamp=self._clock.now(),
                        source="rate_limiter",
                        service=ServiceName.MONITORING,
                        event_type="security_rate_limiter_error",
                        severity=Severity.HIGH,
                        simulation=False,
                        action="fail_closed",
                        correlation_id="",
                    )
                )
            return False

        now = self._time_fn()
        tokens_per_second = rate / 60.0
        actual_burst = self._get_burst_for_key(key, burst)

        if key not in self._buckets:
            tokens = float(actual_burst)
            last_time = now
        else:
            tokens, last_time = self._buckets[key]

        elapsed = now - last_time
        if elapsed > 0:
            tokens += elapsed * tokens_per_second
            if tokens > actual_burst:
                tokens = float(actual_burst)
            last_time = now

        if tokens >= cost:
            self._buckets[key] = (tokens - cost, last_time)
            return True

        self._buckets[key] = (tokens, last_time)
        return False

    def retry_after(self, key: str) -> int:
        try:
            rate, burst = self._get_limits()
        except Exception:
            return 1

        now = self._time_fn()
        tokens_per_second = rate / 60.0
        if tokens_per_second <= 0:
            return 1

        actual_burst = self._get_burst_for_key(key, burst)
        tokens, _ = self._buckets.get(key, (float(actual_burst), now))

        if tokens >= 1:
            return 1

        missing = 1 - tokens
        seconds = math.ceil(missing / tokens_per_second)
        return max(1, seconds)
