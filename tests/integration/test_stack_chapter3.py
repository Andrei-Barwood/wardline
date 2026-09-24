"""Integration test for Chapter 3: Resource limits on live stack."""

import asyncio

import httpx
import pytest

from tests.integration.conftest import (
    Stack,
    open_tcp,
    read_tcp_line,
    roundtrip_udp,
)


@pytest.mark.asyncio
async def test_chapter3_limits_on_live_stack(stack: Stack) -> None:
    # 1. Con burst 2 configurado en ese stack,
    # la tercera petición autenticada seguida a /metrics recibe 429
    # Clave viewer y client id "student-one"
    headers = {
        "Authorization": "Bearer dev-viewer-key",
        "X-Client-Id": "student-one",
    }
    async with httpx.AsyncClient(base_url=stack.base_url, timeout=2.0) as client:
        r1 = await client.get("/metrics", headers=headers)
        assert r1.status_code == 200

        r2 = await client.get("/metrics", headers=headers)
        assert r2.status_code == 200

        r3 = await client.get("/metrics", headers=headers)
        assert r3.status_code == 429
        assert r3.json()["error"]["code"] == "rate_limited"

    # 2. Una línea TCP mayor que el límite cierra la sesión
    reader, writer = await open_tcp(stack.tcp_port)
    try:
        max_bytes = stack.state.settings.tcp_max_message_bytes
        oversized = b"x" * (max_bytes + 200)
        writer.write(oversized)
        await writer.drain()

        error_reply = await read_tcp_line(reader)
        assert error_reply.get("code") == "message_too_large"
        eof = await asyncio.wait_for(reader.readline(), timeout=1.0)
        assert eof == b""
    finally:
        writer.close()
        await writer.wait_closed()

    # 3. Un datagrama UDP mayor que el límite no recibe respuesta en 0.3 s
    max_udp = stack.state.settings.udp_max_datagram_bytes
    oversized_udp = b"U" * (max_udp + 100)
    reply = await roundtrip_udp(stack.udp_port, oversized_udp, timeout=0.3)
    assert reply is None
