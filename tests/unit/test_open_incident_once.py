from wardline.config.settings import Settings
from wardline.contracts import ServiceName, Severity
from wardline.incidents.models import IncidentState
from wardline.incidents.service import IncidentService
from wardline.runtime import build_state


def test_open_incident_once():
    state = build_state(Settings(database_url="sqlite:///:memory:"))

    # Open once
    inc1 = IncidentService.open_if_needed(
        state,
        source="client1",
        service=ServiceName.HTTP,
        severity=Severity.HIGH,
        event_type="anomaly_rate_abuse",
        correlation_id="123",
        simulation=False,
    )
    assert inc1 is not None
    assert inc1.state == IncidentState.DETECTED
    assert state.incidents.get(inc1.id) is not None

    # Attempt to open again with same source and event_type
    inc2 = IncidentService.open_if_needed(
        state,
        source="client1",
        service=ServiceName.HTTP,
        severity=Severity.HIGH,
        event_type="anomaly_rate_abuse",
        correlation_id="456",
        simulation=False,
    )

    assert inc2 is inc1
    assert inc2.correlation_id == "123"  # it returned the existing one
