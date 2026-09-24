from datetime import UTC, datetime

from wardline.contracts import SecurityEvent, ServiceName, Severity
from wardline.monitoring.alerts import select_alerts


def _make_event(
    event_type: str,
    severity: Severity,
    source: str = "test",
    service: ServiceName = ServiceName.HTTP,
) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.now(UTC),
        source=source,
        service=service,
        event_type=event_type,
        severity=severity,
        simulation=False,
        action="test",
        correlation_id="corr-1",
        details={},
    )


def test_alerts_exclude_info_lifecycle() -> None:
    events = [
        _make_event("lifecycle_started", Severity.INFO),
        _make_event("lifecycle_stopped", Severity.INFO),
        _make_event("security_auth_failure", Severity.LOW),
    ]

    alerts = select_alerts(events, min_severity=Severity.INFO)
    types = [a.event_type for a in alerts]
    assert "lifecycle_started" not in types
    assert "lifecycle_stopped" not in types
    assert "security_auth_failure" in types


def test_alerts_include_security_and_anomaly() -> None:
    events = [
        _make_event("security_auth_failure", Severity.LOW),
        _make_event("anomaly_rate_abuse", Severity.MEDIUM),
        _make_event("anomaly_malformed_input", Severity.LOW),
        _make_event("other_event", Severity.HIGH),
    ]

    alerts = select_alerts(events, min_severity=Severity.LOW)
    types = [a.event_type for a in alerts]
    assert types == [
        "security_auth_failure",
        "anomaly_rate_abuse",
        "anomaly_malformed_input",
    ]


def test_alerts_respect_min_severity() -> None:
    events = [
        _make_event("anomaly_malformed_input", Severity.LOW),
        _make_event("anomaly_rate_abuse", Severity.MEDIUM),
        _make_event("anomaly_connection_pressure", Severity.HIGH),
        _make_event("security_critical_breach", Severity.CRITICAL),
    ]

    med_alerts = select_alerts(events, min_severity=Severity.MEDIUM)
    assert [a.event_type for a in med_alerts] == [
        "anomaly_rate_abuse",
        "anomaly_connection_pressure",
        "security_critical_breach",
    ]

    high_alerts = select_alerts(events, min_severity=Severity.HIGH)
    assert [a.event_type for a in high_alerts] == [
        "anomaly_connection_pressure",
        "security_critical_breach",
    ]

    crit_alerts = select_alerts(events, min_severity=Severity.CRITICAL)
    assert [a.event_type for a in crit_alerts] == [
        "security_critical_breach",
    ]
