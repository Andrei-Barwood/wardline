"""Composition of the null laboratory process."""

from datetime import UTC, datetime

import pytest

from wardline.config.settings import Settings, validate_settings
from wardline.contracts import (
    ErrorCode,
    IncidentState,
    SecurityEvent,
    ServiceName,
    Severity,
)
from wardline.errors import WardlineError
from wardline.incidents.models import Incident, new_incident_id
from wardline.runtime import AppState, build_state


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


def test_build_state_returns_app_state() -> None:
    settings = Settings()
    state = build_state(settings)
    assert isinstance(state, AppState)
    assert state.settings is settings
    assert state.started_at.tzinfo is not None


def test_validate_settings_rejects_public_host() -> None:
    with pytest.raises(WardlineError) as caught:
        Settings(http_host="203.0.113.10")
    assert caught.value.code == ErrorCode.validation_error


def test_validate_settings_rejects_non_sqlite_url() -> None:
    with pytest.raises(WardlineError) as caught:
        Settings(database_url="postgres://localhost/wardline")
    assert caught.value.code == ErrorCode.validation_error


def test_validate_settings_accepts_loopback() -> None:
    validate_settings(Settings())
    validate_settings(Settings(http_host="localhost", tcp_host="::1", udp_host="127.0.0.1"))


def test_null_components_do_not_raise() -> None:
    state = build_state(Settings())
    assert state.auth.authenticate(None) is not None
    assert state.auth.authenticate("not-a-key") is not None
    event = _event()
    state.events.add(event)
    assert state.events.list_events() == [event]
    state.audit.append(event)
    assert state.rate_limiter.allow("any") is True
    assert state.quotas.allow("training-client") is True
    now = state.clock.now()
    state.blocks.block(
        "training-client",
        until=now,
        reason="none",
        incident_id="inc_000000000000",
    )
    assert state.blocks.is_blocked("training-client", now) is False
    assert state.blocks.unblock("training-client") is False
    state.health.set_status("http", "ok")
    assert state.health.snapshot()["http"] == "ok"
    state.tcp_stats.bump("bytes_in", 3)
    state.udp_stats.bump("datagrams_received", 1)
    body = state.metrics.to_dict()
    assert body["uptime_seconds"] >= 0
    assert body["tcp"]["bytes_in"] == 3
    assert state.circuit_breakers.allow(ServiceName.TCP) is True
    state.circuit_breakers.record_failure(ServiceName.TCP)
    assert state.anomaly.observe(event) == []
    assert state.config_history.push({"log_level": "INFO"}) == 1
    assert state.config_history.previous() == {"log_level": "INFO"}
    incident = Incident(
        id=new_incident_id(),
        state=IncidentState.DETECTED,
        title="Synthetic",
        source="system",
        service=ServiceName.TCP,
        severity=Severity.HIGH,
        correlation_id="00000000-0000-4000-8000-000000000002",
        simulation=True,
        created_at=now,
        updated_at=now,
    )
    state.incidents.add(incident)
    assert state.incidents.get(incident.id) == incident
    assert state.incidents.list_all() == [incident]
