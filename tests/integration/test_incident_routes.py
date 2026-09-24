import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx

from wardline.api.app import create_app
from wardline.config.settings import Settings
from wardline.contracts import IncidentState, Role, ServiceName, Severity
from wardline.incidents.models import Incident, new_incident_id
from wardline.runtime import AppState, build_state
from wardline.serve import start_tcp


def _create_incident(state: AppState, source: str = "bad-client") -> Incident:
    now = state.clock.now()
    inc = Incident(
        id=new_incident_id(),
        state=IncidentState.DETECTED,
        title="Test incident",
        source=source,
        service=ServiceName.HTTP,
        severity=Severity.HIGH,
        correlation_id="corr-1",
        simulation=True,
        created_at=now,
        updated_at=now,
    )
    state.incidents.add(inc)
    return inc


async def test_viewer_lists_and_gets(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    inc = _create_incident(state)
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # List incidents
        resp = await client.get("/incidents", headers=auth_header("viewer"))
        assert resp.status_code == 200
        data = resp.json()
        assert "incidents" in data
        assert len(data["incidents"]) == 1
        assert data["incidents"][0]["id"] == inc.id

        # Get specific incident
        resp_single = await client.get(f"/incidents/{inc.id}", headers=auth_header("viewer"))
        assert resp_single.status_code == 200
        single_data = resp_single.json()
        assert single_data["id"] == inc.id
        assert single_data["state"] == "DETECTED"

        # Missing incident -> 404
        resp_missing = await client.get(
            "/incidents/inc_000000000000", headers=auth_header("viewer")
        )
        assert resp_missing.status_code == 404
        assert resp_missing.json()["error"]["code"] == "not_found"


async def test_viewer_cannot_acknowledge_even_if_missing_id(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    inc = _create_incident(state)
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # Existing ID -> 403
        resp_real = await client.post(
            f"/incidents/{inc.id}/acknowledge", headers=auth_header("viewer")
        )
        assert resp_real.status_code == 403

        # Nonexistent ID -> 403 (authorization precedes resource check)
        resp_missing = await client.post(
            "/incidents/inc_000000000000/acknowledge", headers=auth_header("viewer")
        )
        assert resp_missing.status_code == 403


async def test_operator_acknowledges(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    inc = _create_incident(state)
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        resp = await client.post(
            f"/incidents/{inc.id}/acknowledge",
            headers=auth_header("operator"),
            json={"note": "investigating breach"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["state"] == "INVESTIGATING"
        assert len(body["actions"]) == 1
        assert body["actions"][0]["action"] == "acknowledge"
        assert body["actions"][0]["detail"] == "investigating breach"


async def test_operator_cannot_contain(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    inc = _create_incident(state)
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        resp = await client.post(f"/incidents/{inc.id}/contain", headers=auth_header("operator"))
        assert resp.status_code == 403


async def test_admin_contains_and_blocks_client(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    inc = _create_incident(state, source="rogue-client")
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # First operator acknowledges
        ack_resp = await client.post(
            f"/incidents/{inc.id}/acknowledge", headers=auth_header("operator")
        )
        assert ack_resp.status_code == 200

        # Admin contains
        cnt_resp = await client.post(
            f"/incidents/{inc.id}/contain",
            headers=auth_header("admin"),
            json={"note": "quarantining client"},
        )
        assert cnt_resp.status_code == 200
        body = cnt_resp.json()
        assert body["state"] == "CONTAINED"

        # Check client is blocked in state
        assert state.blocks.is_blocked("rogue-client", state.clock.now()) is True

        # Traffic from rogue-client receives 403 client_blocked
        headers = dict(auth_header("viewer"))
        headers["X-Client-Id"] = "rogue-client"
        blocked_resp = await client.get("/status", headers=headers)
        assert blocked_resp.status_code == 403
        assert blocked_resp.json()["error"]["code"] == "client_blocked"


async def test_blocked_tcp_client_rejected(settings_factory: Callable[..., Settings]) -> None:
    state = build_state(settings_factory())
    state.blocks.block(
        "blocked-client",
        until=state.clock.now() + timedelta(seconds=300),
        reason="incident",
        incident_id="inc_000000000000",
    )
    tcp_server = await start_tcp(state)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", tcp_server.port)
        hello = {"type": "hello", "client_id": "blocked-client", "token": "dev-viewer-key"}
        writer.write(json.dumps(hello).encode("utf-8") + b"\n")
        await writer.drain()

        line = await asyncio.wait_for(reader.readline(), timeout=1.0)
        resp = json.loads(line)
        assert resp["type"] == "error"
        assert resp["code"] == "client_blocked"

        # Connection should close
        closed_line = await reader.read()
        assert closed_line == b""
        writer.close()
        await writer.wait_closed()
    finally:
        await tcp_server.stop()


def test_block_expires() -> None:
    class ManualClock:
        def __init__(self, now: datetime) -> None:
            self._now = now

        def now(self) -> datetime:
            return self._now

        def advance(self, seconds: float) -> None:
            self._now += timedelta(seconds=seconds)

    start = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)
    clock = ManualClock(start)

    from wardline.clients.blocks import InMemoryBlockRegistry

    registry = InMemoryBlockRegistry()
    registry.block(
        "client-exp",
        until=start + timedelta(seconds=300),
        reason="test",
        incident_id="inc_000000000001",
    )

    assert registry.is_blocked("client-exp", clock.now()) is True
    assert registry.count_active(clock.now()) == 1

    clock.advance(301)
    assert registry.is_blocked("client-exp", clock.now()) is False
    assert registry.count_active(clock.now()) == 0


async def test_second_acknowledge_409(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    inc = _create_incident(state)
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # First ack
        r1 = await client.post(f"/incidents/{inc.id}/acknowledge", headers=auth_header("operator"))
        assert r1.status_code == 200

        # Second ack -> 409
        r2 = await client.post(f"/incidents/{inc.id}/acknowledge", headers=auth_header("operator"))
        assert r2.status_code == 409
        assert r2.json()["error"]["code"] == "invalid_state_transition"

        # Verify only one action persisted
        get_resp = await client.get(f"/incidents/{inc.id}", headers=auth_header("viewer"))
        assert len(get_resp.json()["actions"]) == 1


async def test_invalid_id_format(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # Viewer with bad id formats -> 404
        bad_ids = ["not_an_id", "inc_123", "inc_INVALIDHEX1", "inc_' OR 1=1--"]
        for bad_id in bad_ids:
            r = await client.get(f"/incidents/{bad_id}", headers=auth_header("viewer"))
            assert r.status_code == 404
            assert r.json()["error"]["code"] == "not_found"

        # Viewer POST contain with bad id format -> 403 (authorization precedes format check!)
        r_auth = await client.post("/incidents/not_an_id/contain", headers=auth_header("viewer"))
        assert r_auth.status_code == 403


async def test_resolve_then_retry_unhealthy_409(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    inc = _create_incident(state)
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # Move to INVESTIGATING
        await client.post(f"/incidents/{inc.id}/acknowledge", headers=auth_header("operator"))
        # Move to CONTAINED
        await client.post(f"/incidents/{inc.id}/contain", headers=auth_header("admin"))

        # First resolve from CONTAINED -> moves to RECOVERING, returns 200
        res1 = await client.post(f"/incidents/{inc.id}/resolve", headers=auth_header("admin"))
        assert res1.status_code == 200
        assert res1.json()["state"] == "RECOVERING"

        # Second resolve from RECOVERING -> rechecks unverified health -> 409
        res2 = await client.post(f"/incidents/{inc.id}/resolve", headers=auth_header("admin"))
        assert res2.status_code == 409
        assert res2.json()["error"]["code"] == "invalid_state_transition"


async def test_note_too_long_rejected(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    inc = _create_incident(state)
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # Note longer than 200 chars -> 400
        r_long = await client.post(
            f"/incidents/{inc.id}/acknowledge",
            headers=auth_header("operator"),
            json={"note": "a" * 201},
        )
        assert r_long.status_code == 400
        assert r_long.json()["error"]["code"] == "validation_error"

        # Forbidden key -> 400
        r_extra = await client.post(
            f"/incidents/{inc.id}/acknowledge",
            headers=auth_header("operator"),
            json={"state": "RESOLVED"},
        )
        assert r_extra.status_code == 400
        assert r_extra.json()["error"]["code"] == "validation_error"


async def test_admin_unblock_endpoint(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    now = state.clock.now()
    state.blocks.block(
        "target-client",
        until=now + timedelta(seconds=300),
        reason="test",
        incident_id="inc_000000000001",
    )
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # Operator cannot unblock -> 403
        r_op = await client.post(
            "/admin/clients/target-client/unblock", headers=auth_header("operator")
        )
        assert r_op.status_code == 403

        # Admin unblocks -> 200
        r_admin = await client.post(
            "/admin/clients/target-client/unblock", headers=auth_header("admin")
        )
        assert r_admin.status_code == 200
        assert r_admin.json() == {"status": "unblocked", "client_id": "target-client"}
        assert state.blocks.is_blocked("target-client", state.clock.now()) is False

        # Second unblock when not blocked -> 404
        r_repeat = await client.post(
            "/admin/clients/target-client/unblock", headers=auth_header("admin")
        )
        assert r_repeat.status_code == 404
