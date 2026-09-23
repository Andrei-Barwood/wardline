"""Contract enumerations and value-type defaults."""

import re
from datetime import UTC, datetime

from wardline.contracts import (
    SEVERITY_RANK,
    ErrorCode,
    IncidentState,
    Role,
    SecurityEvent,
    ServiceName,
    Severity,
)
from wardline.incidents.models import new_incident_id


def _event() -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.now(UTC),
        source="system",
        service=ServiceName.HTTP,
        event_type="lifecycle_started",
        severity=Severity.INFO,
        simulation=False,
        action="recorded",
        correlation_id="00000000-0000-4000-8000-000000000001",
    )


def test_roles_are_viewer_operator_admin() -> None:
    assert [role.value for role in Role] == ["viewer", "operator", "admin"]


def test_severity_rank_order() -> None:
    assert SEVERITY_RANK[Severity.INFO] < SEVERITY_RANK[Severity.LOW]
    assert SEVERITY_RANK[Severity.LOW] < SEVERITY_RANK[Severity.MEDIUM]
    assert SEVERITY_RANK[Severity.MEDIUM] < SEVERITY_RANK[Severity.HIGH]
    assert SEVERITY_RANK[Severity.HIGH] < SEVERITY_RANK[Severity.CRITICAL]


def test_incident_states_exact() -> None:
    assert [state.value for state in IncidentState] == [
        "DETECTED",
        "INVESTIGATING",
        "CONTAINED",
        "RECOVERING",
        "RESOLVED",
    ]


def test_error_codes_include_simulation_refused() -> None:
    assert ErrorCode.simulation_refused == "simulation_refused"
    assert "simulation_refused" in {code.value for code in ErrorCode}


def test_security_event_defaults_isolated_details() -> None:
    first = _event()
    second = _event()
    first.details["marker"] = 1
    assert second.details == {}
    assert first.details == {"marker": 1}


def test_new_incident_id_prefix_and_hex() -> None:
    seen = {new_incident_id() for _ in range(20)}
    assert len(seen) == 20
    for value in seen:
        assert re.fullmatch(r"inc_[0-9a-f]{12}", value)
