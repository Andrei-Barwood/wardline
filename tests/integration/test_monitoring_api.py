import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime

import httpx

from wardline.api.app import create_app
from wardline.config.settings import Settings
from wardline.contracts import IncidentState, Role, SecurityEvent, ServiceName, Severity
from wardline.incidents.models import Incident
from wardline.runtime import build_state
from wardline.serve import start_http, start_tcp, start_udp


class _UdpClient(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.packets: asyncio.Queue[bytes] = asyncio.Queue()
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int] | tuple[object, ...]) -> None:
        del addr
        self.packets.put_nowait(data)


async def test_monitoring_routes_require_viewer(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        routes = ["/metrics", "/alerts", "/security/summary"]
        for route in routes:
            # Anonymous -> 401
            resp_anon = await client.get(route)
            assert resp_anon.status_code == 401, f"Expected 401 for anonymous on {route}"

            # Viewer -> 200
            resp_viewer = await client.get(route, headers=auth_header("viewer"))
            assert resp_viewer.status_code == 200, f"Expected 200 for viewer on {route}"

            # Operator -> 200
            resp_operator = await client.get(route, headers=auth_header("operator"))
            assert resp_operator.status_code == 200, f"Expected 200 for operator on {route}"


async def test_summary_zero_keys_present(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory())
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        resp = await client.get("/security/summary", headers=auth_header("viewer"))
        assert resp.status_code == 200
        data = resp.json()

        assert data["open_incidents"] == 0
        assert data["active_blocks"] == 0
        assert data["simulation_events"] == 0
        assert data["truncated"] is False

        expected_severities = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        assert data["by_severity"] == expected_severities

        expected_services = {
            "http": 0,
            "tcp": 0,
            "udp": 0,
            "auth": 0,
            "simulation": 0,
            "incidents": 0,
            "monitoring": 0,
        }
        assert data["by_service"] == expected_services


async def test_summary_counts_simulation_and_open_incidents(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory())

    # Add events
    evt1 = SecurityEvent(
        timestamp=datetime.now(UTC),
        source="client-1",
        service=ServiceName.HTTP,
        event_type="security_test",
        severity=Severity.HIGH,
        simulation=True,
        action="alert",
        correlation_id="c1",
        details={},
    )
    evt2 = SecurityEvent(
        timestamp=datetime.now(UTC),
        source="client-2",
        service=ServiceName.TCP,
        event_type="security_test_2",
        severity=Severity.LOW,
        simulation=False,
        action="alert",
        correlation_id="c2",
        details={},
    )
    state.events.add(evt1)
    state.events.add(evt2)

    # Add incidents: one open (DETECTED), one closed (RESOLVED)
    now = datetime.now(UTC)
    inc_open = Incident(
        id="inc_open000001",
        state=IncidentState.DETECTED,
        title="Open incident",
        source="test",
        service=ServiceName.HTTP,
        severity=Severity.HIGH,
        correlation_id="c1",
        simulation=True,
        created_at=now,
        updated_at=now,
    )
    inc_resolved = Incident(
        id="inc_res0000002",
        state=IncidentState.RESOLVED,
        title="Resolved incident",
        source="test",
        service=ServiceName.TCP,
        severity=Severity.LOW,
        correlation_id="c2",
        simulation=False,
        created_at=now,
        updated_at=now,
    )
    state.incidents.add(inc_open)
    state.incidents.add(inc_resolved)

    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        resp = await client.get("/security/summary", headers=auth_header("viewer"))
        assert resp.status_code == 200
        data = resp.json()

        assert data["simulation_events"] == 1
        assert data["open_incidents"] == 1
        assert data["by_severity"]["HIGH"] == 1
        assert data["by_severity"]["LOW"] == 1
        assert data["by_service"]["http"] == 1
        assert data["by_service"]["tcp"] == 1
        assert data["truncated"] is False


async def test_alerts_api_filtering_and_validation(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))

    evt_lifecycle = SecurityEvent(
        timestamp=datetime.now(UTC),
        source="system",
        service=ServiceName.HTTP,
        event_type="lifecycle_started",
        severity=Severity.INFO,
        simulation=False,
        action="start",
        correlation_id="c0",
        details={},
    )
    evt_auth_fail = SecurityEvent(
        timestamp=datetime.now(UTC),
        source="client-1",
        service=ServiceName.AUTH,
        event_type="security_auth_failure",
        severity=Severity.LOW,
        simulation=False,
        action="reject",
        correlation_id="c1",
        details={},
    )
    evt_anomaly = SecurityEvent(
        timestamp=datetime.now(UTC),
        source="client-2",
        service=ServiceName.TCP,
        event_type="anomaly_rate_abuse",
        severity=Severity.MEDIUM,
        simulation=False,
        action="flag",
        correlation_id="c2",
        details={},
    )
    state.events.add(evt_lifecycle)
    state.events.add(evt_auth_fail)
    state.events.add(evt_anomaly)

    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # Default min_severity=LOW excludes INFO lifecycle but includes LOW and MEDIUM
        resp = await client.get("/alerts", headers=auth_header("viewer"))
        assert resp.status_code == 200
        alerts = resp.json()["alerts"]
        alert_types = [a["event_type"] for a in alerts]
        assert "lifecycle_started" not in alert_types
        assert "security_auth_failure" in alert_types
        assert "anomaly_rate_abuse" in alert_types

        # min_severity=MEDIUM excludes LOW
        resp_med = await client.get("/alerts?min_severity=MEDIUM", headers=auth_header("viewer"))
        assert resp_med.status_code == 200
        med_alerts = resp_med.json()["alerts"]
        med_types = [a["event_type"] for a in med_alerts]
        assert "security_auth_failure" not in med_types
        assert "anomaly_rate_abuse" in med_types

        # Invalid min_severity returns 400
        resp_inv = await client.get("/alerts?min_severity=INVALID", headers=auth_header("viewer"))
        assert resp_inv.status_code == 400


async def test_tcp_stats_increase_after_ping(settings_factory: Callable[..., Settings]) -> None:
    settings = settings_factory()
    state = build_state(settings)
    tcp_server = await start_tcp(state)
    http_server = await start_http(state)

    try:
        http_url = f"http://127.0.0.1:{http_server.port}"
        headers = {"Authorization": "Bearer dev-viewer-key"}
        async with httpx.AsyncClient(base_url=http_url) as client:
            # Check initial metrics
            res1 = await client.get("/metrics", headers=headers)
            assert res1.status_code == 200
            initial_valid = res1.json()["tcp"]["messages_valid"]

            # Connect TCP, send hello, then ping
            reader, writer = await asyncio.open_connection("127.0.0.1", tcp_server.port)
            hello = {"type": "hello", "client_id": "training-client", "token": "dev-viewer-key"}
            writer.write(json.dumps(hello).encode("utf-8") + b"\n")
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=1.0)
            assert b"welcome" in line

            ping = {"type": "ping", "request_id": "p-1"}
            writer.write(json.dumps(ping).encode("utf-8") + b"\n")
            await writer.drain()
            resp_line = await asyncio.wait_for(reader.readline(), timeout=1.0)
            assert b"pong" in resp_line
            writer.close()
            await writer.wait_closed()

            # Check metrics again
            res2 = await client.get("/metrics", headers=headers)
            assert res2.status_code == 200
            final_valid = res2.json()["tcp"]["messages_valid"]
            assert final_valid > initial_valid
    finally:
        await tcp_server.stop()
        await http_server.stop()


async def test_udp_stats_increase_after_beacon(settings_factory: Callable[..., Settings]) -> None:
    settings = settings_factory()
    state = build_state(settings)
    udp_server = await start_udp(state)
    http_server = await start_http(state)

    try:
        http_url = f"http://127.0.0.1:{http_server.port}"
        headers = {"Authorization": "Bearer dev-viewer-key"}
        async with httpx.AsyncClient(base_url=http_url) as client:
            res1 = await client.get("/metrics", headers=headers)
            assert res1.status_code == 200
            initial_valid = res1.json()["udp"]["datagrams_valid"]

            # Send UDP beacon
            loop = asyncio.get_running_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                _UdpClient,
                local_addr=("127.0.0.1", 0),
            )
            try:
                beacon = json.dumps(
                    {
                        "type": "beacon",
                        "client_id": "training-client",
                        "seq": 1,
                        "token": "dev-viewer-key",
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
                transport.sendto(beacon, ("127.0.0.1", udp_server.port))
                raw_reply = await asyncio.wait_for(protocol.packets.get(), timeout=1.0)
                reply = json.loads(raw_reply)
                assert reply["type"] == "beacon_ack"
            finally:
                transport.close()

            # Check metrics again
            res2 = await client.get("/metrics", headers=headers)
            assert res2.status_code == 200
            final_valid = res2.json()["udp"]["datagrams_valid"]
            assert final_valid > initial_valid
    finally:
        await udp_server.stop()
        await http_server.stop()
