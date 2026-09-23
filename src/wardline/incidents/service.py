from wardline.contracts import IncidentState, ServiceName, Severity
from wardline.incidents.models import Incident, new_incident_id
from wardline.runtime import AppState


class IncidentService:
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
                # We map event_type back from title? Or just check if title matches.
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
