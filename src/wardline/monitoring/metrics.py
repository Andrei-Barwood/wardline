"""Health map and the JSON document served later by GET /metrics."""

from datetime import datetime
from typing import Any

from wardline.contracts import Clock
from wardline.monitoring.stats import TransportStats

HEALTH_COMPONENTS = ("http", "tcp", "udp", "database")


class HealthRegistry:
    """Component status used by the future /health route. Defaults to down."""

    def __init__(self) -> None:
        self._status = {name: "down" for name in HEALTH_COMPONENTS}

    def set_status(self, name: str, status: str) -> None:
        if name not in self._status:
            raise KeyError(name)
        if status not in {"ok", "down"}:
            raise ValueError(status)
        self._status[name] = status

    def snapshot(self) -> dict[str, str]:
        return dict(self._status)


class MetricsRegistry:
    """Build the /metrics document from the clock and the current counters."""

    def __init__(
        self,
        *,
        clock: Clock,
        started_at: datetime,
        tcp_stats: TransportStats,
        udp_stats: TransportStats,
    ) -> None:
        self._clock = clock
        self._started_at = started_at
        self._tcp_stats = tcp_stats
        self._udp_stats = udp_stats
        self._http = {
            "requests_total": 0,
            "rate_limited_total": 0,
            "unauthorized_total": 0,
            "forbidden_total": 0,
        }
        self._security = {
            "events_total": 0,
            "alerts_open": 0,
            "incidents_open": 0,
            "blocked_clients": 0,
        }
        self.log_lines_total: int = 0

    def bump(self, section: str, field: str, n: int = 1) -> None:
        sections = {"http": self._http, "security": self._security}
        counters = sections.get(section)
        if counters is None or field not in counters:
            raise KeyError(field)
        counters[field] += n

    def to_dict(self) -> dict[str, Any]:
        elapsed = (self._clock.now() - self._started_at).total_seconds()
        if elapsed < 0:
            elapsed = 0.0
        return {
            "uptime_seconds": elapsed,
            "http": dict(self._http),
            "tcp": self._tcp_stats.as_dict(),
            "udp": self._udp_stats.as_dict(),
            "security": dict(self._security),
        }
