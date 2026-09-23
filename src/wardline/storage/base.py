"""Repository protocols. SQL implementations stay outside this module."""

from typing import Any, Protocol

from wardline.contracts import SecurityEvent, ServiceName, Severity
from wardline.incidents.models import Incident


class EventRepository(Protocol):
    def add(self, event: SecurityEvent) -> None:
        """Persist one security event."""

    def list_events(
        self,
        *,
        limit: int = 100,
        min_severity: Severity | None = None,
        service: ServiceName | None = None,
        simulation: bool | None = None,
    ) -> list[SecurityEvent]:
        """Return matching events, newest first."""


class IncidentRepository(Protocol):
    def add(self, incident: Incident) -> None:
        """Persist a new incident."""

    def get(self, incident_id: str) -> Incident | None:
        """Return the incident or None when the id is unknown."""

    def save(self, incident: Incident) -> None:
        """Replace the stored incident with the same id."""

    def list_all(self) -> list[Incident]:
        """Return every stored incident."""


class ConfigHistory(Protocol):
    def push(self, snapshot: dict[str, Any]) -> int:
        """Store a snapshot and return the new generation number."""

    def previous(self) -> dict[str, Any] | None:
        """Return the latest snapshot, or None when the stack is empty."""

    def current_generation(self) -> int:
        """Return how many generations have been recorded."""
