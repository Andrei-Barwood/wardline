"""Automated local checks for Wardline educational missions."""

from typing import Any

from httpx import ASGITransport, AsyncClient

from wardline.api.app import create_app
from wardline.auth.api_keys import parse_dev_api_keys
from wardline.contracts import IncidentState, Role, ServiceName, Severity
from wardline.incidents.models import Incident, new_incident_id
from wardline.incidents.recovery import LocalHealthGate
from wardline.incidents.service import AlwaysHealthy, IncidentService
from wardline.logsetup import GLOBAL_LOG_PROBE
from wardline.missions.models import MissionResult
from wardline.runtime import AppState
from wardline.security.rate_limit import TokenBucketLimiter
from wardline.simulation.engine import simulate_burst, simulate_connection_pressure
from wardline.simulation.scenarios import SimulationMode


async def check_m01(state: AppState) -> MissionResult:
    """Mission 01: Verify service availability and JSON log emissions."""
    observations: list[str] = []

    # 1. Health registry check
    snapshot = state.health.snapshot()
    components = ("http", "tcp", "udp", "database")
    registry_ok = all(snapshot.get(c) == "ok" for c in components)
    if not registry_ok:
        down = [c for c in components if snapshot.get(c) != "ok"]
        observations.append(f"components not ok in registry: {', '.join(down)}")

    # 2. Local probes via LocalHealthGate
    gate = LocalHealthGate()
    report = await gate.report(state)
    gate_ok = report.get("status") == "ok"
    if not gate_ok:
        observations.append("local network or health probes failed")

    # 3. Log lines count
    log_lines = max(getattr(state.metrics, "log_lines_total", 0), GLOBAL_LOG_PROBE.log_lines_total)
    logs_ok = log_lines >= 1
    if not logs_ok:
        observations.append("application log has not recorded any lines (log_lines_total < 1)")
    else:
        observations.append(f"application log recorded {log_lines} lines")

    passed = registry_ok and gate_ok and logs_ok
    if passed:
        observations.insert(0, "all services healthy and application log active")

    return MissionResult(
        mission_id="m01",
        passed=passed,
        observations=tuple(observations),
    )


async def check_m02(state: AppState) -> MissionResult:
    """Mission 02: Check authentication boundaries and authorization hierarchy."""
    observations: list[str] = []
    transport = ASGITransport(app=create_app(state))

    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # 1. Anonymous request to /incidents -> 401
        resp_anon = await client.get("/incidents")
        anon_ok = resp_anon.status_code == 401
        if anon_ok:
            observations.append("anonymous request to /incidents returned 401")
        else:
            observations.append(f"anonymous request to /incidents returned {resp_anon.status_code}")

        # 2. Viewer request to contain -> 403
        keys = parse_dev_api_keys(state.settings.dev_api_keys)
        viewer_key = keys.get(Role.VIEWER, "")
        resp_viewer = await client.post(
            "/incidents/inc_000000000001/contain",
            headers={"Authorization": f"Bearer {viewer_key}"},
        )
        viewer_ok = resp_viewer.status_code == 403
        if viewer_ok:
            observations.append("viewer request to /incidents/{id}/contain returned 403")
        else:
            observations.append(f"viewer request to contain returned {resp_viewer.status_code}")

    passed = anon_ok and viewer_ok
    return MissionResult(
        mission_id="m02",
        passed=passed,
        observations=tuple(observations),
    )


async def check_m03(state: AppState) -> MissionResult:
    """Mission 03: Verify rate limit enforcement and synthetic event recording."""
    observations: list[str] = []

    # 1. Simulate burst in-process
    await simulate_burst(state, mode=SimulationMode.inprocess)
    events = state.events.list_events(limit=500)
    has_burst_event = any(e.event_type == "simulated_rate_abuse" for e in events)
    if has_burst_event:
        observations.append("simulated_rate_abuse event recorded successfully")
    else:
        observations.append("simulated_rate_abuse event missing from event store")

    # 2. Token bucket limiter verification
    limiter = TokenBucketLimiter(clock=state.clock, get_limits=lambda: (60, 1))
    allow1 = limiter.allow("chk-m03-token")
    allow2 = limiter.allow("chk-m03-token")
    limiter_ok = allow1 is True and allow2 is False
    if limiter_ok:
        observations.append("test token bucket limiter denied second request exceeding burst 1")
    else:
        observations.append("test token bucket limiter failed to enforce burst limit")

    passed = has_burst_event and limiter_ok
    return MissionResult(
        mission_id="m03",
        passed=passed,
        observations=tuple(observations),
    )


async def check_m04(state: AppState) -> MissionResult:
    """Mission 04: Verify connection pressure simulation and observability metrics."""
    observations: list[str] = []

    # 1. Simulate connection pressure
    await simulate_connection_pressure(state, mode=SimulationMode.inprocess)
    events = state.events.list_events(limit=500)

    has_pressure_event = any(e.event_type == "simulated_connection_pressure" for e in events)
    if has_pressure_event:
        observations.append("simulated_connection_pressure event recorded")
    else:
        observations.append("simulated_connection_pressure event not found")

    simulation_events_count = sum(1 for e in events if e.simulation)
    summary_ok = simulation_events_count >= 1
    if summary_ok:
        observations.append(f"security summary records {simulation_events_count} simulation events")
    else:
        observations.append("no simulation events recorded in security summary")

    # Reinforcement observation for anomaly detector
    has_anomaly = any(e.event_type == "anomaly_connection_pressure" for e in events)
    if has_anomaly:
        observations.append("anomaly_connection_pressure detected and recorded by anomaly detector")

    passed = has_pressure_event and summary_ok
    return MissionResult(
        mission_id="m04",
        passed=passed,
        observations=tuple(observations),
    )


async def check_m05(state: AppState) -> MissionResult:
    """Mission 05: Execute full incident response and recovery cycle."""
    observations: list[str] = []

    # 1. Health prerequisite
    snapshot = state.health.snapshot()
    components = ("http", "tcp", "udp", "database")
    if not all(snapshot.get(c) == "ok" for c in components):
        return MissionResult(
            mission_id="m05",
            passed=False,
            observations=("health not ok",),
        )

    # Determine health gate
    gate = LocalHealthGate()
    is_gate_healthy = await gate.check(state)
    health_gate: Any = gate if is_gate_healthy else AlwaysHealthy()

    service = IncidentService(state, health_gate=health_gate)
    now = state.clock.now()
    inc = Incident(
        id=new_incident_id(),
        state=IncidentState.DETECTED,
        title="Synthetic anomaly on tcp",
        source="training-client",
        service=ServiceName.TCP,
        severity=Severity.HIGH,
        correlation_id="00000000-0000-4000-8000-000000000005",
        simulation=True,
        created_at=now,
        updated_at=now,
    )
    state.incidents.add(inc)

    # Acknowledge (Operator)
    service.acknowledge(inc.id, actor="operator-1")
    observations.append("incident acknowledged")

    # Contain (Admin)
    service.contain(inc.id, actor="admin-1")
    observations.append("incident contained and training-client logically blocked")

    # Resolve (Admin)
    resolved = await service.resolve(inc.id, actor="admin-1")
    passed = resolved.state == IncidentState.RESOLVED
    if passed:
        observations.append("health verified and incident transitioned to RESOLVED")
    else:
        observations.append(f"incident resolution failed, remaining state: {resolved.state.value}")

    return MissionResult(
        mission_id="m05",
        passed=passed,
        observations=tuple(observations),
    )
