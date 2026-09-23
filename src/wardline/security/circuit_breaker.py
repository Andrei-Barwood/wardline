import logging
from collections import deque
from collections.abc import Callable
from typing import Literal

from wardline.contracts import Clock, SecurityEvent, ServiceName, Severity

logger = logging.getLogger("wardline.security")


class CircuitBreaker:
    """A circuit breaker protecting a single service."""

    def __init__(
        self,
        *,
        threshold: int,
        window_seconds: float,
        open_seconds: float,
        time_fn: Callable[[], float],
        on_change: Callable[[str], None] | None = None,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.open_seconds = open_seconds
        self.time_fn = time_fn
        self._on_change = on_change

        self._state: Literal["closed", "open", "half_open"] = "closed"
        self._failures: deque[float] = deque()
        self._opened_at: float = 0.0
        self._half_open_probe_allowed: bool = False

    @property
    def state(self) -> Literal["closed", "open", "half_open"]:
        self._update_state()
        return self._state

    def _update_state(self) -> None:
        if self._state == "open":
            if self.time_fn() >= self._opened_at + self.open_seconds:
                self._transition("half_open")
                self._half_open_probe_allowed = True

    def _transition(self, new_state: Literal["closed", "open", "half_open"]) -> None:
        self._state = new_state
        if self._on_change is not None:
            try:
                self._on_change(new_state)
            except Exception:
                logger.exception("Circuit breaker callback failed")

    def allow(self) -> bool:
        self._update_state()
        if self._state == "closed":
            return True
        if self._state == "half_open":
            if self._half_open_probe_allowed:
                self._half_open_probe_allowed = False
                return True
            return False
        return False

    def record_success(self) -> None:
        self._update_state()
        if self._state == "half_open":
            self._failures.clear()
            self._transition("closed")

    def record_failure(self) -> None:
        self._update_state()
        now = self.time_fn()
        if self._state == "half_open":
            self._opened_at = now
            self._transition("open")
        elif self._state == "closed":
            self._failures.append(now)
            cutoff = now - self.window_seconds
            while self._failures and self._failures[0] < cutoff:
                self._failures.popleft()
            if len(self._failures) >= self.threshold:
                self._opened_at = now
                self._transition("open")


class CircuitHooks:
    """Fallback base for doubles."""

    def allow(self, service: ServiceName) -> bool:
        return True

    def record_success(self, service: ServiceName) -> None:
        pass

    def record_failure(self, service: ServiceName) -> None:
        pass


class CircuitBreakerRegistry(CircuitHooks):
    """Per-service breakers registry."""

    def __init__(
        self,
        *,
        threshold: int = 5,
        window_seconds: float = 60.0,
        open_seconds: float = 30.0,
        time_fn: Callable[[], float] | None = None,
        audit_callback: Callable[[SecurityEvent], None] | None = None,
        clock: "Clock | None" = None,
    ) -> None:
        import time

        self.time_fn = time_fn if time_fn is not None else time.monotonic
        self.audit_callback = audit_callback
        self.clock = clock

        def make_on_change(service: ServiceName) -> Callable[[str], None]:
            def on_change(state_str: str) -> None:
                if state_str == "open" and self.audit_callback is not None:
                    evt = SecurityEvent(
                        timestamp=self.clock.now() if self.clock else None,
                        source="circuit_breaker",
                        service=service,
                        event_type="security_circuit_open",
                        severity=Severity.HIGH,
                        simulation=False,
                        action="opened",
                        correlation_id="",
                    )
                    self.audit_callback(evt)

            return on_change

        self._breakers = {
            s: CircuitBreaker(
                threshold=threshold,
                window_seconds=window_seconds,
                open_seconds=open_seconds,
                time_fn=self.time_fn,
                on_change=make_on_change(s),
            )
            for s in [ServiceName.HTTP, ServiceName.TCP, ServiceName.UDP]
        }

    def allow(self, service: ServiceName) -> bool:
        breaker = self._breakers.get(service)
        return breaker.allow() if breaker else True

    def record_success(self, service: ServiceName) -> None:
        breaker = self._breakers.get(service)
        if breaker:
            breaker.record_success()

    def record_failure(self, service: ServiceName) -> None:
        breaker = self._breakers.get(service)
        if breaker:
            breaker.record_failure()


def note_failure(state: object, service: ServiceName) -> None:
    """Tolerate a null registry."""
    registry = getattr(state, "circuit_breakers", None)
    if registry is not None and hasattr(registry, "record_failure"):
        registry.record_failure(service)


def note_success(state: object, service: ServiceName) -> None:
    """Tolerate a null registry."""
    registry = getattr(state, "circuit_breakers", None)
    if registry is not None and hasattr(registry, "record_success"):
        registry.record_success(service)
