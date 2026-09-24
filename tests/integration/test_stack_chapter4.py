"""Integration test for Chapter 4: Observability and synthetic events on live stack."""

import httpx
import pytest

from tests.integration.conftest import Stack


@pytest.mark.asyncio
async def test_chapter4_events_visible(stack: Stack) -> None:
    headers_operator = {"Authorization": "Bearer dev-operator-key"}
    headers_viewer = {"Authorization": "Bearer dev-viewer-key"}

    async with httpx.AsyncClient(base_url=stack.base_url, timeout=2.0) as client:
        # 1. Operator ejecuta los cuatro escenarios inprocess vía HTTP
        for idx, scenario in enumerate(
            ("burst", "invalid_messages", "connection_pressure", "udp_burst"), start=1
        ):
            headers = {**headers_operator, "X-Client-Id": f"operator-sim-{idx}"}
            resp = await client.post(
                "/simulation/run",
                headers=headers,
                json={"scenario": scenario, "mode": "inprocess"},
            )
            assert resp.status_code == 200, f"Scenario {scenario} failed: {resp.text}"

        # 2. Viewer GET /events contiene los cuatro event_type sintéticos
        resp_events = await client.get(
            "/events?limit=200", headers={**headers_viewer, "X-Client-Id": "viewer-events"}
        )
        assert resp_events.status_code == 200
        event_types = {e["event_type"] for e in resp_events.json()["events"]}
        expected_types = {
            "simulated_rate_abuse",
            "simulated_invalid_input",
            "simulated_connection_pressure",
            "simulated_udp_burst",
        }
        assert expected_types.issubset(event_types), (
            f"Missing event types: {expected_types - event_types}"
        )

        # 3. Viewer GET /security/summary simulation_events >= 4
        resp_summary = await client.get(
            "/security/summary", headers={**headers_viewer, "X-Client-Id": "viewer-summary"}
        )
        assert resp_summary.status_code == 200
        summary = resp_summary.json()
        assert summary.get("simulation_events", 0) >= 4

        # 4. Viewer GET /alerts?min_severity=MEDIUM incluye al menos uno
        resp_alerts = await client.get(
            "/alerts?min_severity=MEDIUM",
            headers={**headers_viewer, "X-Client-Id": "viewer-alerts"},
        )
        assert resp_alerts.status_code == 200
        alerts = resp_alerts.json()["alerts"]
        assert len(alerts) >= 1
