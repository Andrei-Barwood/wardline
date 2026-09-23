"""Circuit breakers. The first registry stays closed and records nothing."""

from wardline.contracts import ServiceName


class CircuitBreakerRegistry:
    """Per-service breakers. allow() is always true until a later prompt."""

    def allow(self, service: ServiceName) -> bool:
        del service
        return True

    def record_failure(self, service: ServiceName) -> None:
        del service
