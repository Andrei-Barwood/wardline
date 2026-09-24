from datetime import UTC, datetime
from pathlib import Path

import pytest

from wardline.contracts import ErrorCode, IncidentState, ServiceName, Severity
from wardline.errors import WardlineError
from wardline.incidents.machine import transition
from wardline.incidents.models import Incident, new_incident_id
from wardline.incidents.service import AlwaysHealthy, IncidentService
from wardline.runtime import build_state
from wardline.storage.memory import MemoryIncidentRepository
from wardline.storage.sqlite import SqliteIncidentRepository


def _make_incident(
    state: IncidentState = IncidentState.DETECTED, source: str = "test-client"
) -> Incident:
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)
    return Incident(
        id=new_incident_id(),
        state=state,
        title="Test incident",
        source=source,
        service=ServiceName.HTTP,
        severity=Severity.HIGH,
        correlation_id="corr-1",
        simulation=True,
        created_at=now,
        updated_at=now,
    )


def test_happy_path_states() -> None:
    inc = _make_incident(IncidentState.DETECTED)
    now = datetime(2026, 9, 24, 12, 1, 0, tzinfo=UTC)

    # DETECTED -> acknowledge -> INVESTIGATING
    inc1 = transition(inc, "acknowledge", actor="operator-1", now=now, note="Acknowledged")
    assert inc1.state == IncidentState.INVESTIGATING
    assert len(inc1.actions) == 1
    assert inc1.actions[0].action == "acknowledge"
    assert inc1.actions[0].from_state == IncidentState.DETECTED
    assert inc1.actions[0].to_state == IncidentState.INVESTIGATING
    assert inc1.actions[0].detail == "Acknowledged"

    # INVESTIGATING -> contain -> CONTAINED
    now2 = datetime(2026, 9, 24, 12, 2, 0, tzinfo=UTC)
    inc2 = transition(inc1, "contain", actor="admin-1", now=now2, note="Contained")
    assert inc2.state == IncidentState.CONTAINED
    assert len(inc2.actions) == 2
    assert inc2.actions[1].action == "contain"
    assert inc2.actions[1].from_state == IncidentState.INVESTIGATING
    assert inc2.actions[1].to_state == IncidentState.CONTAINED

    # CONTAINED -> resolve -> RECOVERING
    now3 = datetime(2026, 9, 24, 12, 3, 0, tzinfo=UTC)
    inc3 = transition(inc2, "resolve", actor="admin-1", now=now3, note="Resolving")
    assert inc3.state == IncidentState.RECOVERING
    assert len(inc3.actions) == 3
    assert inc3.actions[2].action == "resolve"
    assert inc3.actions[2].from_state == IncidentState.CONTAINED
    assert inc3.actions[2].to_state == IncidentState.RECOVERING

    # RECOVERING -> resolve -> RESOLVED
    now4 = datetime(2026, 9, 24, 12, 4, 0, tzinfo=UTC)
    inc4 = transition(inc3, "resolve", actor="admin-1", now=now4, note="Resolved")
    assert inc4.state == IncidentState.RESOLVED
    assert len(inc4.actions) == 4
    assert inc4.actions[3].from_state == IncidentState.RECOVERING
    assert inc4.actions[3].to_state == IncidentState.RESOLVED


def test_illegal_transitions_raise() -> None:
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)
    states = [
        IncidentState.DETECTED,
        IncidentState.INVESTIGATING,
        IncidentState.CONTAINED,
        IncidentState.RECOVERING,
        IncidentState.RESOLVED,
    ]

    for st in states:
        inc = _make_incident(st)

        # acknowledge is only legal from DETECTED
        if st != IncidentState.DETECTED:
            with pytest.raises(WardlineError) as exc_info:
                transition(inc, "acknowledge", actor="op", now=now)
            assert exc_info.value.code == ErrorCode.invalid_state_transition

        # contain is only legal from INVESTIGATING
        if st != IncidentState.INVESTIGATING:
            with pytest.raises(WardlineError) as exc_info:
                transition(inc, "contain", actor="admin", now=now)
            assert exc_info.value.code == ErrorCode.invalid_state_transition

        # resolve is only legal from CONTAINED and RECOVERING
        if st not in {IncidentState.CONTAINED, IncidentState.RECOVERING}:
            with pytest.raises(WardlineError) as exc_info:
                transition(inc, "resolve", actor="admin", now=now)
            assert exc_info.value.code == ErrorCode.invalid_state_transition

        # invalid action
        with pytest.raises(WardlineError) as exc_info:
            transition(inc, "unknown_action", actor="admin", now=now)
        assert exc_info.value.code == ErrorCode.invalid_state_transition


def test_resolve_stops_at_recovering_before_health() -> None:
    inc = _make_incident(IncidentState.CONTAINED)
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)

    # In transition, resolve moves CONTAINED to RECOVERING, not RESOLVED
    res = transition(inc, "resolve", actor="admin-1", now=now)
    assert res.state == IncidentState.RECOVERING


def test_input_incident_is_not_mutated() -> None:
    inc = _make_incident(IncidentState.DETECTED)
    original_state = inc.state
    original_actions = inc.actions
    original_updated_at = inc.updated_at
    now = datetime(2026, 9, 24, 12, 1, 0, tzinfo=UTC)

    new_inc = transition(inc, "acknowledge", actor="op-1", now=now)

    assert inc.state == original_state
    assert inc.actions == original_actions
    assert inc.updated_at == original_updated_at
    assert new_inc is not inc
    assert new_inc.state == IncidentState.INVESTIGATING


def test_resolve_reaches_resolved_when_healthy(tmp_path: Path) -> None:
    from wardline.config.settings import Settings

    settings = Settings(database_url=f"sqlite:///{tmp_path / 'w.db'}")
    state = build_state(settings)
    service = IncidentService(state, health_gate=AlwaysHealthy())

    # Create incident in DETECTED
    inc = _make_incident(IncidentState.DETECTED)
    state.incidents.add(inc)

    # Acknowledge -> INVESTIGATING
    ack = service.acknowledge(inc.id, actor="operator-1")
    assert ack.state == IncidentState.INVESTIGATING

    # Contain -> CONTAINED
    cnt = service.contain(inc.id, actor="admin-1")
    assert cnt.state == IncidentState.CONTAINED

    # Resolve with AlwaysHealthy reaches RESOLVED!
    res = service.resolve(inc.id, actor="admin-1")
    assert res.state == IncidentState.RESOLVED
    assert len(res.actions) == 4  # acknowledge, contain, resolve->RECOVERING, resolve->RESOLVED


@pytest.mark.parametrize("repo_type", ["memory", "sqlite"])
def test_sqlite_and_memory_match(repo_type: str, tmp_path: Path) -> None:
    if repo_type == "memory":
        repo = MemoryIncidentRepository()
    else:
        repo = SqliteIncidentRepository(f"sqlite:///{tmp_path / f'{repo_type}.db'}")

    inc = _make_incident(IncidentState.DETECTED)
    repo.add(inc)

    # Duplicate add raises validation_error
    with pytest.raises(WardlineError) as exc_info:
        repo.add(inc)
    assert exc_info.value.code == ErrorCode.validation_error

    # get
    fetched = repo.get(inc.id)
    assert fetched is not None
    assert fetched.id == inc.id
    assert fetched.state == IncidentState.DETECTED
    assert len(fetched.actions) == 0

    # transition and save
    now = datetime(2026, 9, 24, 12, 1, 0, tzinfo=UTC)
    updated = transition(fetched, "acknowledge", actor="op-1", now=now, note="note 1")
    repo.save(updated)

    fetched2 = repo.get(inc.id)
    assert fetched2 is not None
    assert fetched2.state == IncidentState.INVESTIGATING
    assert len(fetched2.actions) == 1
    assert fetched2.actions[0].action == "acknowledge"
    assert fetched2.actions[0].detail == "note 1"

    # list_all
    all_incidents = repo.list_all()
    assert len(all_incidents) == 1
    assert all_incidents[0].id == inc.id
    assert all_incidents[0].state == IncidentState.INVESTIGATING

    # save unknown id raises not_found
    fake_inc = _make_incident(IncidentState.DETECTED)
    with pytest.raises(WardlineError) as exc_info:
        repo.save(fake_inc)
    assert exc_info.value.code == ErrorCode.not_found
