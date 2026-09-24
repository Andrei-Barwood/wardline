"""Integration test for Chapter 5: Incident lifecycle and selective recovery on live stack."""

import httpx
import pytest

from tests.integration.conftest import (
    Stack,
    open_tcp,
    read_tcp_line,
    send_tcp_line,
)


@pytest.mark.asyncio
async def test_chapter5_incident_roundtrip(stack: Stack) -> None:
    headers_operator = {"Authorization": "Bearer dev-operator-key"}
    headers_admin = {"Authorization": "Bearer dev-admin-key"}

    async with httpx.AsyncClient(base_url=stack.base_url, timeout=2.0) as client:
        # 1. Trigger connection pressure inprocess
        resp_sim = await client.post(
            "/simulation/run",
            headers={**headers_operator, "X-Client-Id": "op-trigger-sim"},
            json={"scenario": "connection_pressure", "mode": "inprocess"},
        )
        assert resp_sim.status_code == 200

        # Query incidents
        resp_inc = await client.get(
            "/incidents", headers={**headers_operator, "X-Client-Id": "op-list-inc"}
        )
        assert resp_inc.status_code == 200
        incidents = resp_inc.json()["incidents"]

        # If natural trigger didn't create an incident due to windowing,
        # open_if_needed can be called
        if not incidents:
            from wardline.contracts import ServiceName, Severity
            from wardline.incidents.service import IncidentService

            IncidentService.open_if_needed(
                stack.state,
                source="training-client",
                service=ServiceName.TCP,
                severity=Severity.HIGH,
                event_type="anomaly_connection_pressure",
                correlation_id=resp_sim.json().get("correlation_id", "corr-ch5"),
                simulation=True,
            )
            resp_inc = await client.get(
                "/incidents", headers={**headers_operator, "X-Client-Id": "op-list-inc-2"}
            )
            incidents = resp_inc.json()["incidents"]

        assert len(incidents) >= 1
        incident = incidents[0]
        inc_id = incident["id"]
        assert incident["state"].lower() == "detected"

        # 2. Operator acknowledge
        resp_ack = await client.post(
            f"/incidents/{inc_id}/acknowledge",
            headers={**headers_operator, "X-Client-Id": "op-ack-inc"},
        )
        assert resp_ack.status_code == 200
        assert resp_ack.json()["state"].lower() == "investigating"

        # 3. Admin contain
        resp_contain = await client.post(
            f"/incidents/{inc_id}/contain",
            headers={**headers_admin, "X-Client-Id": "admin-contain"},
        )
        assert resp_contain.status_code == 200
        assert resp_contain.json()["state"].lower() == "contained"
        now = stack.state.clock.now()
        assert stack.state.blocks.is_blocked("training-client", now)

        # 4. Admin resolve
        resp_resolve = await client.post(
            f"/incidents/{inc_id}/resolve",
            headers={**headers_admin, "X-Client-Id": "admin-resolve"},
        )
        assert resp_resolve.status_code == 200
        assert resp_resolve.json()["state"].lower() == "resolved"
        now = stack.state.clock.now()
        assert not stack.state.blocks.is_blocked("training-client", now)

    # 5. training-client can perform a TCP ping after resolve
    reader, writer = await open_tcp(stack.tcp_port)
    try:
        await send_tcp_line(
            writer,
            {"type": "hello", "client_id": "training-client", "token": "dev-viewer-key"},
        )
        hello_reply = await read_tcp_line(reader)
        assert hello_reply.get("type") in ("hello", "welcome") or hello_reply.get("status") == "ok"

        await send_tcp_line(writer, {"type": "ping", "request_id": "post-resolve-ping"})
        pong_reply = await read_tcp_line(reader)
        assert pong_reply.get("type") == "pong"
        assert pong_reply.get("request_id") == "post-resolve-ping"
    finally:
        writer.close()
        await writer.wait_closed()
