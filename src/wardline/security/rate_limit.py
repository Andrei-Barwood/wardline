"""Rate limiter protocol. The first implementation allows every call."""

from typing import Protocol


class RateLimiter(Protocol):
    def allow(self, key: str, *, cost: int = 1) -> bool:
        """Return True when the caller may proceed."""


class InMemoryRateLimiter:
    """Placeholder bucket that never rejects. Prompt 10 replaces the body."""

    def allow(self, key: str, *, cost: int = 1) -> bool:
        del key, cost
        return True
