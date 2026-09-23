class QuotaTracker:
    """Track accepted messages per client up to a fixed limit."""

    def __init__(self, *, limit: int = 1000) -> None:
        self._limit = limit
        self._used: dict[str, int] = {}

    def allow(self, client_id: str) -> bool:
        """Increment and return True if within quota, False otherwise."""
        current = self._used.get(client_id, 0)
        if current >= self._limit:
            return False
        self._used[client_id] = current + 1
        return True

    def used(self, client_id: str) -> int:
        """Return the number of messages consumed by this client."""
        return self._used.get(client_id, 0)
