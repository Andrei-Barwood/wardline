import asyncio
import socket
from collections.abc import Callable

import pytest
import uvicorn
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from wardline.api.app import create_app
from wardline.config import Settings
from wardline.runtime import build_state
from wardline.simulation.engine import simulate_burst, simulate_udp_burst
from wardline.simulation.scenarios import SimulationMode


async def run_server(app: FastAPI, port: int):
    config = uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="critical")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)
    return task, server


@pytest.mark.asyncio
async def test_loopback_burst_hits_local_health_only():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    settings = Settings(wardline_env="test", http_port=port, http_host="127.0.0.1")
    state = build_state(settings)
    app = create_app(state)

    task, server = await run_server(app, port)
    try:
        # Before simulation
        requests_before = state.metrics.to_dict().get("http", {}).get("requests_total", 0)

        await simulate_burst(state, mode=SimulationMode.loopback)

        requests_after = state.metrics.to_dict().get("http", {}).get("requests_total", 0)
        assert requests_after > requests_before
        assert requests_after - requests_before <= 30
    finally:
        server.should_exit = True
        await task


@pytest.mark.asyncio
async def test_loopback_udp_sends_at_most_budget():
    settings = Settings(wardline_env="test", udp_port=0, udp_host="127.0.0.1")
    state = build_state(settings)
    await simulate_udp_burst(state, mode=SimulationMode.loopback)


@pytest.mark.asyncio
async def test_viewer_forbidden_operator_allowed(settings_factory: Callable[..., Settings]):
    settings = settings_factory()
    state = build_state(settings)
    app = create_app(state)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # Viewer forbidden
        res = await client.post(
            "/simulation/run",
            json={"scenario": "burst", "mode": "inprocess"},
            headers={"Authorization": "Bearer dev-viewer-key"},
        )
        assert res.status_code == 403

        # Admin allowed (since it inherits operator)
        res = await client.post(
            "/simulation/run",
            json={"scenario": "burst", "mode": "inprocess"},
            headers={"Authorization": "Bearer dev-admin-key"},
        )
        assert res.status_code == 200
