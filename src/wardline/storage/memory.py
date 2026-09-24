"""In-memory repositories used by unit tests and the first process composition."""

from typing import Any

from wardline.contracts import SEVERITY_RANK, ErrorCode, SecurityEvent, ServiceName, Severity
from wardline.errors import WardlineError
from wardline.incidents.models import Incident


class MemoryEventRepository:
    """Event store that keeps rows in process order."""

    def __init__(self) -> None:
        self._events: list[tuple[int, SecurityEvent]] = []
        self._next_id = 1

    def add(self, event: SecurityEvent) -> None:
        self._events.append((self._next_id, event))
        self._next_id += 1

    def list_events(
        self,
        *,
        limit: int = 100,
        min_severity: Severity | None = None,
        service: ServiceName | None = None,
        simulation: bool | None = None,
    ) -> list[SecurityEvent]:
        bounded = min(5001, max(1, limit))
        matched: list[SecurityEvent] = []
        sorted_events = sorted(self._events, key=lambda x: (x[1].timestamp, x[0]), reverse=True)
        for _, event in sorted_events:
            if (
                min_severity is not None
                and SEVERITY_RANK[event.severity] < SEVERITY_RANK[min_severity]
            ):
                continue
            if service is not None and event.service != service:
                continue
            if simulation is not None and event.simulation is not simulation:
                continue
            matched.append(event)
            if len(matched) >= bounded:
                break
        return matched


class MemoryIncidentRepository:
    """Incident store keyed by the public incident id."""

    def __init__(self) -> None:
        self._items: dict[str, Incident] = {}
        self._order: list[str] = []

    def add(self, incident: Incident) -> None:
        if incident.id in self._items:
            raise WardlineError(ErrorCode.validation_error, "incident already exists")
        self._items[incident.id] = incident
        self._order.append(incident.id)

    def get(self, incident_id: str) -> Incident | None:
        return self._items.get(incident_id)

    def save(self, incident: Incident) -> None:
        if incident.id not in self._items:
            raise WardlineError(ErrorCode.not_found, "incident not found")
        self._items[incident.id] = incident

    def list_all(self) -> list[Incident]:
        return [self._items[incident_id] for incident_id in self._order]


class MemoryConfigHistory:
    """Stack of configuration snapshots. previous() removes the latest entry."""

    def __init__(self) -> None:
        self._stack: list[dict[str, Any]] = []
        self._generation = 0

    def push(self, snapshot: dict[str, Any]) -> int:
        self._stack.append(dict(snapshot))
        self._generation += 1
        return self._generation

    def previous(self) -> dict[str, Any] | None:
        if not self._stack:
            return None
        self._generation += 1
        return dict(self._stack.pop())

    def current_generation(self) -> int:
        return self._generation

    def close(self) -> None:
        pass
