"""Counters for the TCP and UDP services."""

TCP_FIELDS = (
    "connections_accepted",
    "connections_rejected",
    "connections_active",
    "messages_valid",
    "messages_invalid",
    "bytes_in",
    "timeouts",
)

UDP_FIELDS = (
    "datagrams_received",
    "datagrams_valid",
    "datagrams_dropped",
    "bytes_in",
)


class TransportStats:
    """Monotonic counters for one transport. Unknown fields are rejected."""

    def __init__(self, fields: tuple[str, ...]) -> None:
        self._counters = {name: 0 for name in fields}

    def bump(self, field: str, n: int = 1) -> None:
        if field not in self._counters:
            raise KeyError(field)
        self._counters[field] += n

    def as_dict(self) -> dict[str, int]:
        return dict(self._counters)
