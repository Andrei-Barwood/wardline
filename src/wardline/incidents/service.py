import inspect
import re
from datetime import timedelta
from typing import Any, Protocol

from wardline.auth.api_keys import parse_dev_api_keys
from wardline.clients.identity import validate_client_id
from wardline.contracts import (
    ErrorCode,
    IncidentState,
    SecurityEvent,
    ServiceName,
    Severity,
)
from wardline.errors import WardlineError
from wardline.incidents.machine import transition
from wardline.incidents.models import Incident, new_incident_id
from wardline.incidents.recovery import LocalHealthGate
from wardline.runtime import AppState
from wardline.security.events import record_event
from wardline.security.redaction import redact

_INCIDENT_ID_PATTERN = re.compile(r"^inc_[0-9a-f]{12}$")


def validate_incident_id(incident_id: str) -> str:
    """Validate that incident_id adheres to inc_ followed by 12 lowercase hex characters."""
    if not _INCIDENT_ID_PATTERN.match(incident_id):
        raise WardlineError(ErrorCode.not_found, "incident not found")
    return incident_id


class HealthGate(Protocol):
    """Protocol for checking system health before completing resolution."""

    def check(self) -> Any:
        """Return True if health passes, False otherwise."""


class AlwaysHealthy:
    def check(self) -> bool:
        return True


class UnverifiedHealth:
    def check(self) -> bool:
        return False


class IncidentService:
    def __init__(self, state: AppState, health_gate: Any | None = None) -> None:
        self.state = state
        self.health_gate: Any = (
            health_gate if health_gate is not None else LocalHealthGate()
        )

    async def _check_health(self) -> tuple[bool, dict[str, Any] | None]:
        gate = self.health_gate
        check_fn = getattr(gate, "check", None)
        if check_fn is None:
            return False, None
        try:
            res = check_fn(self.state)
        except TypeError:
            res = check_fn()
        if inspect.isawaitable(res):
            is_healthy = bool(await res)
        else:
            is_healthy = bool(res)

        report: dict[str, Any] | None = None
        report_fn = getattr(gate, "report", None)
        if report_fn is not None:
            try:
                rep = report_fn(self.state)
            except TypeError:
                rep = report_fn()
            if inspect.isawaitable(rep):
                report = await rep
            else:
                report = rep
        return is_healthy, report

    def _redact_note(self, note: str) -> str:
        if not note:
            return ""
        secrets = tuple(parse_dev_api_keys(self.state.settings.dev_api_keys).values())
        return str(redact(note, secrets=secrets))

    def get(self, incident_id: str) -> Incident:
        validate_incident_id(incident_id)
        incident = self.state.incidents.get(incident_id)
        if incident is None:
            raise WardlineError(ErrorCode.not_found, "incident not found")
        return incident

    def list_all(self) -> list[Incident]:
        return self.state.incidents.list_all()

    def acknowledge(self, incident_id: str, *, actor: str, note: str = "") -> Incident:
        incident = self.get(incident_id)
        redacted_note = self._redact_note(note)
        now = self.state.clock.now()
        updated = transition(incident, "acknowledge", actor=actor, now=now, note=redacted_note)
        self.state.incidents.save(updated)
        return updated

    def contain(self, incident_id: str, *, actor: str, note: str = "") -> Incident:
        incident = self.get(incident_id)
        redacted_note = self._redact_note(note)
        now = self.state.clock.now()
        updated = transition(incident, "contain", actor=actor, now=now, note=redacted_note)

        # Logical blocking of synthetic client if source is not system and valid
        if incident.source != "system":
            try:
                valid_client = validate_client_id(incident.source)
                ttl = timedelta(seconds=self.state.settings.block_ttl_seconds)
                until = now + ttl
                self.state.blocks.block(
                    valid_client,
                    until=until,
                    reason=incident.id,
                    incident_id=incident.id,
                )
                record_event(
                    self.state,
                    SecurityEvent(
                        timestamp=now,
                        source=valid_client,
                        service=ServiceName.INCIDENTS,
                        event_type="security_client_blocked",
                        severity=Severity.HIGH,
                        simulation=incident.simulation,
                        action="blocked",
                        correlation_id=incident.correlation_id,
                        details={"incident_id": incident.id, "until": until.isoformat()},
                    ),
                )
            except WardlineError:
                pass

        self.state.incidents.save(updated)
        return updated

    async def resolve(self, incident_id: str, *, actor: str, note: str = "") -> Incident:
        """Resolve an incident, coordinating with HealthGate.

        If state is CONTAINED: moves to RECOVERING (saves action). Then checks health.
        If healthy: moves to RESOLVED, performs selective unblock, saves action.
        If unhealthy: remains in RECOVERING, returns recovering incident (200).

        If state is RECOVERING: checks health.
        If healthy: moves to RESOLVED, performs selective unblock, saves action.
        If unhealthy: raises WardlineError(invalid_state_transition, details={"health": report}).
        """
        incident = self.get(incident_id)
        redacted_note = self._redact_note(note)
        now = self.state.clock.now()

        if incident.state == IncidentState.CONTAINED:
            # First resolve moves to RECOVERING
            recovering = transition(incident, "resolve", actor=actor, now=now, note=redacted_note)
            self.state.incidents.save(recovering)

            # Check health gate
            is_healthy, _ = await self._check_health()
            if is_healthy:
                resolved = transition(
                    recovering, "resolve", actor=actor, now=now, note=redacted_note
                )
                if incident.source != "system":
                    try:
                        valid_client = validate_client_id(incident.source)
                        self.state.blocks.unblock_incident(valid_client, incident.id)
                    except WardlineError:
                        pass
                self.state.incidents.save(resolved)
                return resolved

            return recovering

        elif incident.state == IncidentState.RECOVERING:
            is_healthy, report = await self._check_health()
            if not is_healthy:
                details = {"health": report} if report is not None else None
                raise WardlineError(
                    ErrorCode.invalid_state_transition,
                    "invalid state transition",
                    details=details,
                )

            resolved = transition(incident, "resolve", actor=actor, now=now, note=redacted_note)
            if incident.source != "system":
                try:
                    valid_client = validate_client_id(incident.source)
                    self.state.blocks.unblock_incident(valid_client, incident.id)
                except WardlineError:
                    pass
            self.state.incidents.save(resolved)
            return resolved

        else:
            return transition(incident, "resolve", actor=actor, now=now, note=redacted_note)

    @staticmethod
    def _title_for(event_type: str, service: ServiceName) -> str:
        name = event_type.replace("anomaly_", "").replace("_", " ").capitalize()
        return f"{name} on {service.value}"

    @staticmethod
    def open_if_needed(
        state: AppState,
        *,
        source: str,
        service: ServiceName,
        severity: Severity,
        event_type: str,
        correlation_id: str,
        simulation: bool,
    ) -> Incident | None:
        title = IncidentService._title_for(event_type, service)

        for incident in state.incidents.list_all():
            if incident.source == source and incident.state != IncidentState.RESOLVED:
                expected_prefix = event_type.replace("anomaly_", "").replace("_", " ").capitalize()
                if incident.title.startswith(expected_prefix):
                    return incident

        now = state.clock.now()
        incident = Incident(
            id=new_incident_id(),
            state=IncidentState.DETECTED,
            title=title,
            source=source,
            service=service,
            severity=severity,
            correlation_id=correlation_id,
            simulation=simulation,
            created_at=now,
            updated_at=now,
        )
        state.incidents.add(incident)
        return incident
