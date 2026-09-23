import socket

import pytest
from httpx import ASGITransport, AsyncClient

from wardline.api.app import create_app
from wardline.config import Settings
from wardline.runtime import build_state
from wardline.simulation.engine import (
    simulate_burst,
    simulate_connection_pressure,
    simulate_invalid_messages,
    simulate_udp_burst,
)
from wardline.simulation.guard import assert_loopback
from wardline.simulation.scenarios import SimulationMode, SimulationRefused


@pytest.mark.asyncio
async def test_inprocess_does_not_open_sockets(monkeypatch):
    def fake_socket(*args, **kwargs):
        raise RuntimeError("Network is disabled in inprocess mode")

    monkeypatch.setattr(socket, "socket", fake_socket)

    state = build_state(Settings(wardline_env="test"))
    for scenario in [
        simulate_burst,
        simulate_udp_burst,
        simulate_connection_pressure,
        simulate_invalid_messages,
    ]:
        res = await scenario(state, mode=SimulationMode.inprocess)
        assert not res.refused


def test_assert_loopback_accepts_localhost():
    assert_loopback("127.0.0.1")
    assert_loopback("localhost")
    assert_loopback("::1")


def test_assert_loopback_rejects_external():
    for host in ["203.0.113.10", "8.8.8.8", "10.0.0.1", "0.0.0.0", "example.com", ""]:
        with pytest.raises(SimulationRefused) as exc:
            assert_loopback(host)
        assert exc.value.refused
        assert exc.value.reason == "non_loopback_target"


@pytest.mark.asyncio
async def test_route_schema_rejects_host_parameter_and_socket_not_called(monkeypatch):
    def fake_socket(*args, **kwargs):
        raise RuntimeError("socket.socket should not be called")

    monkeypatch.setattr(socket, "socket", fake_socket)

    state = build_state(Settings(wardline_env="test"))
    app = create_app(state)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        res = await client.post(
            "/simulation/run",
            json={"scenario": "burst", "mode": "inprocess", "host": "8.8.8.8"},
            headers={"Authorization": "Bearer dev-admin-key"},
        )
        assert res.status_code == 400
        assert "validation_error" in res.text
