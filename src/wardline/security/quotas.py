"""Per-client quotas. The first tracker accepts every message."""


class QuotaTracker:
    """Count of accepted messages. This stand-in does not count or reject."""

    def allow(self, client_id: str) -> bool:
        del client_id
        return True
