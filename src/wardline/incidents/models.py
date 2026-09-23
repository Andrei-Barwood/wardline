"""Incident value types. The state machine arrives in a later prompt."""

import uuid
from dataclasses import dataclass
from datetime import datetime

from wardline.contracts import IncidentState, ServiceName, Severity


def new_incident_id() -> str:
    """Return an id of the form inc_ plus twelve lowercase hex characters."""
    return f"inc_{uuid.uuid4().hex[:12]}"


@dataclass(frozen=True)
class IncidentAction:
    at: datetime
    actor: str
    action: str
    from_state: IncidentState
    to_state: IncidentState
    detail: str


@dataclass(frozen=True)
class Incident:
    id: str
    state: IncidentState
    title: str
    source: str
    service: ServiceName
    severity: Severity
    correlation_id: str
    simulation: bool
    created_at: datetime
    updated_at: datetime
    actions: tuple[IncidentAction, ...] = ()
