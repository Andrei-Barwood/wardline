"""Security tests for privilege boundaries and anti-tampering."""

import asyncio
import json
from collections.abc import Callable

import httpx
from fastapi import APIRouter, Depends

from wardline.api.app import create_app
from wardline.api.deps import require_role
from wardline.config.settings import Settings
from wardline.contracts import Role
from wardline.runtime import build_state
from wardline.serve import start_tcp


async def _open(port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection("127.0.0.1", port)


async def _send(writer: asyncio.StreamWriter, payload: dict[str, object]) -> None:
    writer.write(json.dumps(payload).encode("utf-8") + b"\n")
    await writer.drain()


async def _read(reader: asyncio.StreamReader, timeout: float = 1.0) -> dict[str, object]:
    line = await asyncio.wait_for(reader.readline(), timeout)
    assert line
    parsed = json.loads(line)
    assert isinstance(parsed, dict)
    return parsed


async def test_client_cannot_set_own_role(
    settings_factory: Callable[..., Settings],
) -> None:
    """Client sending role=admin with a viewer token receives welcome with role=viewer."""
    state = build_state(settings_factory())
    running = await start_tcp(state)
    try:
        reader, writer = await _open(running.port)
        # Malicious hello: claims to be admin, but only provides viewer token
        await _send(
            writer,
            {
                "type": "hello",
                "client_id": "sneaky-client",
                "role": "admin",
                "token": "dev-viewer-key",
            },
        )
        welcome = await _read(reader)
        assert welcome["type"] == "welcome"
        assert welcome["role"] == "viewer"
        writer.close()
        await writer.wait_closed()
    finally:
        await running.stop()


async def test_no_x_role_header(
    settings_factory: Callable[..., Settings],
) -> None:
    """Sending X-Role: admin with viewer credentials to an admin endpoint is still 403."""
    state = build_state(settings_factory())
    app = create_app(state)
    test_router = APIRouter()

    @test_router.post("/_test/admin_only", dependencies=[Depends(require_role(Role.ADMIN))])
    def admin_action() -> dict[str, str]:
        return {"action": "executed"}

    app.include_router(test_router)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.post(
            "/_test/admin_only",
            headers={
                "Authorization": "Bearer dev-viewer-key",
                "X-Role": "admin",
            },
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "forbidden"
