from datetime import UTC, datetime, timedelta

from wardline.monitoring.metrics import MetricsRegistry
from wardline.monitoring.stats import TCP_FIELDS, UDP_FIELDS, TransportStats


class FixedClock:
    def __init__(self, current: datetime) -> None:
        self._current = current

    def now(self) -> datetime:
        return self._current

    def advance(self, delta: timedelta) -> None:
        self._current += delta


def test_metrics_contains_all_sections() -> None:
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)
    clock = FixedClock(now)
    tcp_stats = TransportStats(TCP_FIELDS)
    udp_stats = TransportStats(UDP_FIELDS)
    registry = MetricsRegistry(
        clock=clock,
        started_at=now,
        tcp_stats=tcp_stats,
        udp_stats=udp_stats,
    )

    data = registry.to_dict()

    # Top-level keys
    assert "uptime_seconds" in data
    assert isinstance(data["uptime_seconds"], (int, float))
    assert data["uptime_seconds"] >= 0

    assert "http" in data
    assert data["http"] == {
        "requests_total": 0,
        "rate_limited_total": 0,
        "unauthorized_total": 0,
        "forbidden_total": 0,
    }
    for k, v in data["http"].items():
        assert isinstance(v, int), f"http.{k} is not int"

    assert "tcp" in data
    assert data["tcp"] == {
        "connections_accepted": 0,
        "connections_rejected": 0,
        "connections_active": 0,
        "messages_valid": 0,
        "messages_invalid": 0,
        "bytes_in": 0,
        "timeouts": 0,
    }
    for k, v in data["tcp"].items():
        assert isinstance(v, int), f"tcp.{k} is not int"

    assert "udp" in data
    assert data["udp"] == {
        "datagrams_received": 0,
        "datagrams_valid": 0,
        "datagrams_dropped": 0,
        "bytes_in": 0,
    }
    for k, v in data["udp"].items():
        assert isinstance(v, int), f"udp.{k} is not int"

    assert "security" in data
    assert data["security"] == {
        "events_total": 0,
        "alerts_open": 0,
        "incidents_open": 0,
        "blocked_clients": 0,
    }
    for k, v in data["security"].items():
        assert isinstance(v, int), f"security.{k} is not int"


def test_uptime_non_negative() -> None:
    started_at = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)
    # Clock is behind started_at
    clock = FixedClock(started_at - timedelta(seconds=10))
    tcp_stats = TransportStats(TCP_FIELDS)
    udp_stats = TransportStats(UDP_FIELDS)
    registry = MetricsRegistry(
        clock=clock,
        started_at=started_at,
        tcp_stats=tcp_stats,
        udp_stats=udp_stats,
    )

    data = registry.to_dict()
    assert data["uptime_seconds"] == 0.0
