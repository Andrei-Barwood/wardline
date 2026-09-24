"""Integration test verifying that SQLite persistence survives full stack restart."""

from pathlib import Path

import httpx
import pytest

from wardline.config.settings import Settings
from wardline.contracts import IncidentState, ServiceName, Severity
from wardline.incidents.models import Incident
from wardline.runtime import build_state
from wardline.serve import start_http, start_tcp, start_udp


@pytest.mark.asyncio
async def test_sqlite_restart_keeps_events(tmp_path: Path) -> None:
    db_file = tmp_path / "wardline.db"
    settings = Settings(
        http_host="127.0.0.1",
        tcp_host="127.0.0.1",
        udp_host="127.0.0.1",
        http_port=0,
        tcp_port=0,
        udp_port=0,
        database_url=f"sqlite:///{db_file}",
        dev_api_keys="viewer:dev-viewer-key,operator:dev-operator-key,admin:dev-admin-key",
    )

    # 1. Start Stack 1
    state1 = build_state(settings)
    srv_http1 = await start_http(state1)
    srv_tcp1 = await start_tcp(state1)
    srv_udp1 = await start_udp(state1)

    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{srv_http1.port}", timeout=2.0
        ) as client1:
            # Trigger inprocess simulation to record events
            resp_sim = await client1.post(
                "/simulation/run",
                headers={"Authorization": "Bearer dev-operator-key", "X-Client-Id": "op-sim-1"},
                json={"scenario": "burst", "mode": "inprocess"},
            )
            assert resp_sim.status_code == 200

            # Create an incident directly in sqlite repository
            now = state1.clock.now()
            inc = Incident(
                id="inc_123456abcdef",
                state=IncidentState.DETECTED,
                title="Test Persistence Incident",
                source="training-client",
                service=ServiceName.TCP,
                severity=Severity.HIGH,
                created_at=now,
                updated_at=now,
                correlation_id="corr-restart-1",
                simulation=True,
            )
            state1.incidents.add(inc)
    finally:
        await srv_http1.stop()
        await srv_tcp1.stop()
        await srv_udp1.stop()
        if hasattr(state1.events, "engine"):
            state1.events.engine.dispose()
        if hasattr(state1.incidents, "engine"):
            state1.incidents.engine.dispose()

    # 2. Start Stack 2 pointing to the exact same database file
    state2 = build_state(settings)
    srv_http2 = await start_http(state2)
    srv_tcp2 = await start_tcp(state2)
    srv_udp2 = await start_udp(state2)

    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{srv_http2.port}", timeout=2.0
        ) as client2:
            # Events must survive the restart
            resp_events = await client2.get(
                "/events?limit=50",
                headers={"Authorization": "Bearer dev-viewer-key", "X-Client-Id": "view-events-2"},
            )
            assert resp_events.status_code == 200
            events = resp_events.json()["events"]
            assert any(e["event_type"] == "simulated_rate_abuse" for e in events)

            # Incidents must survive the restart and remain in DETECTED
            resp_inc = await client2.get(
                "/incidents/inc_123456abcdef",
                headers={"Authorization": "Bearer dev-viewer-key", "X-Client-Id": "view-inc-2"},
            )
            assert resp_inc.status_code == 200
            inc_data = resp_inc.json()
            assert inc_data["id"] == "inc_123456abcdef"
            assert inc_data["state"].lower() == "detected"
    finally:
        await srv_http2.stop()
        await srv_tcp2.stop()
        await srv_udp2.stop()
        if hasattr(state2.events, "engine"):
            state2.events.engine.dispose()
        if hasattr(state2.incidents, "engine"):
            state2.incidents.engine.dispose()
