"""Frozen enumerations and value types shared by every Wardline module."""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field


class Role(StrEnum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class IncidentState(StrEnum):
    DETECTED = "DETECTED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RECOVERING = "RECOVERING"
    RESOLVED = "RESOLVED"


class ServiceName(StrEnum):
    HTTP = "http"
    TCP = "tcp"
    UDP = "udp"
    AUTH = "auth"
    SIMULATION = "simulation"
    INCIDENTS = "incidents"
    MONITORING = "monitoring"


class ErrorCode(StrEnum):
    unauthorized = "unauthorized"
    forbidden = "forbidden"
    invalid_message = "invalid_message"
    message_too_large = "message_too_large"
    rate_limited = "rate_limited"
    quota_exceeded = "quota_exceeded"
    connection_limit = "connection_limit"
    timeout = "timeout"
    circuit_open = "circuit_open"
    client_blocked = "client_blocked"
    invalid_state_transition = "invalid_state_transition"
    simulation_refused = "simulation_refused"
    not_found = "not_found"
    validation_error = "validation_error"
    internal = "internal"


class SecurityEvent(BaseModel):
    """One structured security record. details is a fresh dict per instance."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    source: str
    service: ServiceName
    event_type: str
    severity: Severity
    simulation: bool
    action: str
    correlation_id: str
    details: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")


@dataclass(frozen=True)
class Principal:
    client_id: str
    role: Role
    authenticated: bool


class Clock(Protocol):
    def now(self) -> datetime:
        """Return the current timezone-aware UTC time."""


class SystemClock:
    """Clock backed by the operating system, always in UTC."""

    def now(self) -> datetime:
        return datetime.now(UTC)
