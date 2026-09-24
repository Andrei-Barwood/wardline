from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx

from wardline.api.app import create_app
from wardline.config.settings import Settings
from wardline.contracts import IncidentState, Role, ServiceName, Severity
from wardline.incidents.models import Incident, new_incident_id
from wardline.runtime import AppState, build_state


def _setup_incident(state: AppState) -> Incident:
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)
    inc = Incident(
        id=new_incident_id(),
        state=IncidentState.DETECTED,
        title="Sec auth test",
        source="attacker",
        service=ServiceName.HTTP,
        severity=Severity.HIGH,
        correlation_id="c-sec",
        simulation=False,
        created_at=now,
        updated_at=now,
    )
    state.incidents.add(inc)
    return inc


async def test_privilege_boundaries_on_incident_routes(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=50))
    inc = _setup_incident(state)
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # 1. Anonymous: all return 401
        assert (await client.get("/incidents")).status_code == 401
        assert (await client.get(f"/incidents/{inc.id}")).status_code == 401
        assert (await client.post(f"/incidents/{inc.id}/acknowledge")).status_code == 401
        assert (await client.post(f"/incidents/{inc.id}/contain")).status_code == 401
        assert (await client.post(f"/incidents/{inc.id}/resolve")).status_code == 401
        assert (await client.post("/admin/clients/test/unblock")).status_code == 401

        # 2. Viewer: can read, forbidden to mutate (403)
        assert (await client.get("/incidents", headers=auth_header("viewer"))).status_code == 200
        assert (
            await client.get(f"/incidents/{inc.id}", headers=auth_header("viewer"))
        ).status_code == 200
        assert (
            await client.post(
                f"/incidents/{inc.id}/acknowledge", headers=auth_header("viewer")
            )
        ).status_code == 403
        assert (
            await client.post(
                f"/incidents/{inc.id}/contain", headers=auth_header("viewer")
            )
        ).status_code == 403
        assert (
            await client.post(
                f"/incidents/{inc.id}/resolve", headers=auth_header("viewer")
            )
        ).status_code == 403
        assert (
            await client.post("/admin/clients/test/unblock", headers=auth_header("viewer"))
        ).status_code == 403

        # 3. Operator: can read and acknowledge, forbidden to contain/resolve/unblock (403)
        assert (
            await client.post(
                f"/incidents/{inc.id}/acknowledge", headers=auth_header("operator")
            )
        ).status_code == 200
        assert (
            await client.post(
                f"/incidents/{inc.id}/contain", headers=auth_header("operator")
            )
        ).status_code == 403
        assert (
            await client.post(
                f"/incidents/{inc.id}/resolve", headers=auth_header("operator")
            )
        ).status_code == 403
        assert (
            await client.post("/admin/clients/test/unblock", headers=auth_header("operator"))
        ).status_code == 403

        # 4. Admin: can contain and resolve
        assert (
            await client.post(
                f"/incidents/{inc.id}/contain", headers=auth_header("admin")
            )
        ).status_code == 200
        assert (
            await client.post(
                f"/incidents/{inc.id}/resolve", headers=auth_header("admin")
            )
        ).status_code == 200


async def test_blocked_admin_client_id_isolated(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    now = state.clock.now()
    # Block admin-1
    state.blocks.block(
        "admin-1",
        until=now + timedelta(seconds=300),
        reason="compromised",
        incident_id="inc_000000000001",
    )
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # Blocked admin-1 receives 403 client_blocked
        headers_blocked = dict(auth_header("admin"))
        headers_blocked["X-Client-Id"] = "admin-1"
        resp = await client.get("/status", headers=headers_blocked)
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "client_blocked"

        # Another admin (admin-2) using the SAME admin key can unblock admin-1
        headers_admin2 = dict(auth_header("admin"))
        headers_admin2["X-Client-Id"] = "admin-2"
        unblock_resp = await client.post(
            "/admin/clients/admin-1/unblock", headers=headers_admin2
        )
        assert unblock_resp.status_code == 200
        assert unblock_resp.json()["status"] == "unblocked"

        # Now admin-1 can access again
        resp_after = await client.get("/status", headers=headers_blocked)
        assert resp_after.status_code == 200
