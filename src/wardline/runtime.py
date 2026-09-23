"""Composition root. Builds an AppState without opening sockets or a database."""

from dataclasses import dataclass
from datetime import datetime

from wardline.audit.log import AuditLog, NullAuditLog
from wardline.auth.provider import AllowAllAuth, AuthProvider
from wardline.clients.blocks import BlockRegistry, InMemoryBlockRegistry
from wardline.config.settings import Settings, validate_settings
from wardline.contracts import Clock, SystemClock
from wardline.monitoring.metrics import HealthRegistry, MetricsRegistry
from wardline.monitoring.stats import TCP_FIELDS, UDP_FIELDS, TransportStats
from wardline.security.anomaly import AnomalyDetector
from wardline.security.circuit_breaker import CircuitBreakerRegistry
from wardline.security.quotas import QuotaTracker
from wardline.security.rate_limit import InMemoryRateLimiter, RateLimiter
from wardline.storage.base import ConfigHistory, EventRepository, IncidentRepository
from wardline.storage.memory import (
    MemoryConfigHistory,
    MemoryEventRepository,
    MemoryIncidentRepository,
)


@dataclass
class AppState:
    """Shared objects for one Wardline process."""

    settings: Settings
    started_at: datetime
    clock: Clock
    auth: AuthProvider
    events: EventRepository
    incidents: IncidentRepository
    metrics: MetricsRegistry
    rate_limiter: RateLimiter
    quotas: QuotaTracker
    blocks: BlockRegistry
    health: HealthRegistry
    tcp_stats: TransportStats
    udp_stats: TransportStats
    circuit_breakers: CircuitBreakerRegistry
    audit: AuditLog
    config_history: ConfigHistory
    anomaly: AnomalyDetector
    bindings: dict[str, str]


def build_state(settings: Settings, *, clock: Clock | None = None) -> AppState:
    """Validate settings and wire the null or in-memory components.

    The data directory is created only when a later prompt persists SQLite.
    This function does not listen on a port and does not contact the network.
    """
    validate_settings(settings)
    active_clock = SystemClock() if clock is None else clock
    started_at = active_clock.now()
    tcp_stats = TransportStats(TCP_FIELDS)
    udp_stats = TransportStats(UDP_FIELDS)
    return AppState(
        settings=settings,
        started_at=started_at,
        clock=active_clock,
        auth=AllowAllAuth(),
        events=MemoryEventRepository(),
        incidents=MemoryIncidentRepository(),
        metrics=MetricsRegistry(
            clock=active_clock,
            started_at=started_at,
            tcp_stats=tcp_stats,
            udp_stats=udp_stats,
        ),
        rate_limiter=InMemoryRateLimiter(),
        quotas=QuotaTracker(),
        blocks=InMemoryBlockRegistry(),
        health=HealthRegistry(),
        tcp_stats=tcp_stats,
        udp_stats=udp_stats,
        circuit_breakers=CircuitBreakerRegistry(),
        audit=NullAuditLog(),
        config_history=MemoryConfigHistory(),
        anomaly=AnomalyDetector(),
        bindings={
            "http": f"{settings.http_host}:{settings.http_port}",
            "tcp": f"{settings.tcp_host}:{settings.tcp_port}",
            "udp": f"{settings.udp_host}:{settings.udp_port}",
        },
    )
