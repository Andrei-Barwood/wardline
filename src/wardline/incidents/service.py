import re
from datetime import timedelta
from typing import Protocol

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

    def check(self) -> bool:
        """Return True if health passes, False otherwise."""


class AlwaysHealthy:
    def check(self) -> bool:
        return True


class UnverifiedHealth:
    def check(self) -> bool:
        return False


class IncidentService:
    def __init__(self, state: AppState, health_gate: HealthGate | None = None) -> None:
        self.state = state
        self.health_gate: HealthGate = (
            health_gate if health_gate is not None else UnverifiedHealth()
        )

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

    def resolve(self, incident_id: str, *, actor: str, note: str = "") -> Incident:
        """Resolve an incident, coordinating with HealthGate.

        resolve llama a transition(..., "resolve") que deja RECOVERING,
        luego llama a un protocolo HealthGate.check() -> bool.
        En este prompt el HealthGate por defecto es AlwaysHealthy en tests
        que lo pidan y UnverifiedHealth en producción, cuyo check() devuelve False.
        Así, sin el prompt 17, resolve deja RECOVERING y responde 200, no 409,
        porque la transición a RECOVERING sí fue legal. El 409 del contrato aparece
        cuando se reintenta resolve desde RECOVERING y la salud sigue en False: el
        segundo resolve intenta cerrar y la salud falla, 409, estado se queda RECOVERING.
        Primer resolve desde CONTAINED: siempre puede entrar en RECOVERING aunque
        la salud falle; el fallo de salud impide RESOLVED.
        Ajusta el mensaje 409 a invalid_state_transition.
        Esta semántica queda congelada para el prompt 17.
        """
        incident = self.get(incident_id)
        redacted_note = self._redact_note(note)
        now = self.state.clock.now()

        if incident.state == IncidentState.CONTAINED:
            # First resolve moves to RECOVERING
            recovering = transition(incident, "resolve", actor=actor, now=now, note=redacted_note)
            self.state.incidents.save(recovering)

            # Check health gate
            if self.health_gate.check():
                resolved = transition(
                    recovering, "resolve", actor=actor, now=now, note=redacted_note
                )
                if incident.source != "system":
                    try:
                        self.state.blocks.unblock(validate_client_id(incident.source))
                    except WardlineError:
                        pass
                self.state.incidents.save(resolved)
                return resolved

            return recovering

        elif incident.state == IncidentState.RECOVERING:
            if not self.health_gate.check():
                raise WardlineError(ErrorCode.invalid_state_transition, "invalid state transition")

            resolved = transition(incident, "resolve", actor=actor, now=now, note=redacted_note)
            if incident.source != "system":
                try:
                    self.state.blocks.unblock(validate_client_id(incident.source))
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
