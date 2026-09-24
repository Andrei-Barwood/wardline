from datetime import timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from wardline.api.app import create_app
from wardline.auth.api_keys import parse_dev_api_keys
from wardline.contracts import IncidentState, Role, ServiceName, Severity
from wardline.incidents.models import Incident, new_incident_id
from wardline.incidents.service import AlwaysHealthy, IncidentService
from wardline.runtime import build_state
from wardline.serve import start_http, start_tcp, start_udp


@pytest.mark.integration
async def test_full_recovery_resolves_and_unblocks(settings_factory) -> None:
    settings = settings_factory(http_port=0, tcp_port=0, udp_port=0, rate_limit_burst=20)
    state = build_state(settings)

    http_server = await start_http(state)
    tcp_server = await start_tcp(state)
    udp_server = await start_udp(state)

    keys = parse_dev_api_keys(state.settings.dev_api_keys)
    admin_key = keys[Role.ADMIN]
    headers = {"Authorization": f"Bearer {admin_key}"}

    try:
        transport = ASGITransport(app=create_app(state))
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            now = state.clock.now()
            inc = Incident(
                id=new_incident_id(),
                state=IncidentState.DETECTED,
                title="Synthetic test anomaly",
                source="client-alpha",
                service=ServiceName.TCP,
                severity=Severity.HIGH,
                correlation_id="00000000-0000-4000-8000-000000000001",
                simulation=False,
                created_at=now,
                updated_at=now,
            )
            state.incidents.add(inc)

            # 1. Acknowledge -> INVESTIGATING
            resp = await client.post(f"/incidents/{inc.id}/acknowledge", headers=headers)
            assert resp.status_code == 200
            assert resp.json()["state"] == IncidentState.INVESTIGATING.value

            # 2. Contain -> CONTAINED & block client-alpha
            resp = await client.post(f"/incidents/{inc.id}/contain", headers=headers)
            assert resp.status_code == 200
            assert resp.json()["state"] == IncidentState.CONTAINED.value
            assert state.blocks.is_blocked("client-alpha", state.clock.now()) is True

            # 3. Resolve -> With healthy local TCP/UDP servers, completes to RESOLVED and unblocks!
            resp = await client.post(f"/incidents/{inc.id}/resolve", headers=headers)
            assert resp.status_code == 200
            body = resp.json()
            assert body["state"] == IncidentState.RESOLVED.value
            # Actions show transition history
            assert len(body["actions"]) >= 3
            assert state.blocks.is_blocked("client-alpha", state.clock.now()) is False
    finally:
        await udp_server.stop()
        await tcp_server.stop()
        await http_server.stop()


@pytest.mark.integration
async def test_failed_health_stays_recovering(settings_factory) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    keys = parse_dev_api_keys(state.settings.dev_api_keys)
    admin_key = keys[Role.ADMIN]
    headers = {"Authorization": f"Bearer {admin_key}"}

    transport = ASGITransport(app=create_app(state))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        now = state.clock.now()
        inc = Incident(
            id=new_incident_id(),
            state=IncidentState.CONTAINED,
            title="Synthetic test anomaly",
            source="client-unhealthy",
            service=ServiceName.TCP,
            severity=Severity.HIGH,
            correlation_id="00000000-0000-4000-8000-000000000002",
            simulation=False,
            created_at=now,
            updated_at=now,
        )
        state.incidents.add(inc)
        state.blocks.block(
            "client-unhealthy",
            until=now + timedelta(seconds=state.settings.block_ttl_seconds),
            reason="incident",
            incident_id=inc.id,
        )

        # Force TCP down in registry so LocalHealthGate check fails
        state.health.set_status("tcp", "down")

        # First resolve from CONTAINED: transitions to RECOVERING and returns 200
        resp1 = await client.post(f"/incidents/{inc.id}/resolve", headers=headers)
        assert resp1.status_code == 200
        assert resp1.json()["state"] == IncidentState.RECOVERING.value
        assert state.incidents.get(inc.id).state == IncidentState.RECOVERING
        assert state.blocks.is_blocked("client-unhealthy", state.clock.now()) is True

        # Second resolve from RECOVERING: health check still fails, responds with 409
        resp2 = await client.post(f"/incidents/{inc.id}/resolve", headers=headers)
        assert resp2.status_code == 409
        err = resp2.json()["error"]
        assert err["code"] == "invalid_state_transition"
        assert "details" in err
        assert "health" in err["details"]
        assert err["details"]["health"]["status"] == "degraded"
        # State remains RECOVERING and client remains blocked
        assert state.incidents.get(inc.id).state == IncidentState.RECOVERING
        assert state.blocks.is_blocked("client-unhealthy", state.clock.now()) is True


@pytest.mark.integration
async def test_unblock_is_selective_per_incident(settings_factory) -> None:
    state = build_state(settings_factory())
    now = state.clock.now()

    # Client has two incidents
    inc1 = Incident(
        id=new_incident_id(),
        state=IncidentState.CONTAINED,
        title="Incident 1",
        source="client-multi",
        service=ServiceName.TCP,
        severity=Severity.HIGH,
        correlation_id="00000000-0000-4000-8000-000000000003",
        simulation=False,
        created_at=now,
        updated_at=now,
    )
    inc2 = Incident(
        id=new_incident_id(),
        state=IncidentState.CONTAINED,
        title="Incident 2",
        source="client-multi",
        service=ServiceName.UDP,
        severity=Severity.HIGH,
        correlation_id="00000000-0000-4000-8000-000000000004",
        simulation=False,
        created_at=now,
        updated_at=now,
    )
    state.incidents.add(inc1)
    state.incidents.add(inc2)

    ttl = timedelta(seconds=state.settings.block_ttl_seconds)
    state.blocks.block("client-multi", until=now + ttl, reason="inc1", incident_id=inc1.id)
    state.blocks.block("client-multi", until=now + ttl, reason="inc2", incident_id=inc2.id)
    assert state.blocks.is_blocked("client-multi", now) is True

    # Use AlwaysHealthy gate to test selective unblock logic
    service = IncidentService(state, health_gate=AlwaysHealthy())

    # Resolve incident 1
    res1 = await service.resolve(inc1.id, actor="admin-1")
    assert res1.state == IncidentState.RESOLVED

    # Client-multi MUST still be blocked because inc2 is still active!
    assert state.blocks.is_blocked("client-multi", now) is True

    # Resolve incident 2
    res2 = await service.resolve(inc2.id, actor="admin-1")
    assert res2.state == IncidentState.RESOLVED

    # Now client-multi is completely unblocked!
    assert state.blocks.is_blocked("client-multi", now) is False


@pytest.mark.integration
async def test_manual_block_and_unblock(settings_factory) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    keys = parse_dev_api_keys(state.settings.dev_api_keys)
    admin_key = keys[Role.ADMIN]
    headers = {"Authorization": f"Bearer {admin_key}"}

    transport = ASGITransport(app=create_app(state))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Invalid client ID regex (IP format, symbols) returns 400 validation_error
        resp_bad_ip = await client.post("/admin/clients/192.168.1.1/block", headers=headers)
        assert resp_bad_ip.status_code == 400
        assert resp_bad_ip.json()["error"]["code"] == "validation_error"

        resp_bad_chars = await client.post("/admin/clients/bad@client/block", headers=headers)
        assert resp_bad_chars.status_code == 400
        assert resp_bad_chars.json()["error"]["code"] == "validation_error"

        # Valid client ID can be manually blocked
        resp_block = await client.post(
            "/admin/clients/client-manual/block",
            headers=headers,
            json={"ttl_seconds": 300},
        )
        assert resp_block.status_code == 200
        body = resp_block.json()
        assert body["client_id"] == "client-manual"
        assert body["blocked"] is True
        assert state.blocks.is_blocked("client-manual", state.clock.now()) is True

        # Unblock client
        resp_unblock = await client.post(
            "/admin/clients/client-manual/unblock",
            headers=headers,
        )
        assert resp_unblock.status_code == 200
        assert resp_unblock.json()["status"] == "unblocked"
        assert resp_unblock.json()["client_id"] == "client-manual"
        assert state.blocks.is_blocked("client-manual", state.clock.now()) is False
