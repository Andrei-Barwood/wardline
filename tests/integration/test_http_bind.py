"""The HTTP server binds to loopback and can be stopped."""

from collections.abc import Callable

import httpx

from wardline.config.settings import Settings
from wardline.runtime import build_state
from wardline.serve import start_http


async def test_http_binds_loopback_only(settings_factory: Callable[..., Settings]) -> None:
    state = build_state(settings_factory(http_port=0, tcp_port=0, udp_port=0))
    running = await start_http(state)
    try:
        assert running.port != 0
        sockets = running.server.servers[0].sockets or []
        assert sockets[0].getsockname()[0] == "127.0.0.1"
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{running.port}",
            timeout=2,
        ) as client:
            response = await client.get("/version")
        assert response.status_code == 200
        health = await _health(running.port)
        assert health.status_code == 503
        assert health.json()["status"] == "degraded"
    finally:
        await running.stop()


async def _health(port: int) -> httpx.Response:
    async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=2) as client:
        return await client.get("/health")
