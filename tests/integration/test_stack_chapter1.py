"""Integration test for Chapter 1: Live stack service responses."""

import httpx
import pytest

from tests.integration.conftest import (
    Stack,
    open_tcp,
    read_tcp_line,
    roundtrip_udp,
    send_tcp_line,
)


@pytest.mark.asyncio
async def test_chapter1_services_answer(stack: Stack, caplog: pytest.LogCaptureFixture) -> None:
    # Verify test stack uses isolated tmp_path, not repo data directory
    db_path = stack.state.settings.database_url.removeprefix("sqlite:///")
    assert not db_path.endswith("data/wardline.db")

    # 1. HTTP endpoints
    async with httpx.AsyncClient(base_url=stack.base_url, timeout=2.0) as client:
        # GET /version 200
        resp_ver = await client.get("/version")
        assert resp_ver.status_code == 200
        assert "version" in resp_ver.json()

        # GET /health 200
        resp_health = await client.get("/health")
        assert resp_health.status_code == 200
        assert resp_health.json()["status"] == "ok"

        corr_id = resp_health.headers.get("x-correlation-id")
        assert corr_id is not None

        # Line of log with correlation id after the HTTP request
        matched_logs = [r for r in caplog.records if getattr(r, "correlation_id", None) == corr_id]
        assert len(matched_logs) >= 1

    # 2. TCP ping pong
    reader, writer = await open_tcp(stack.tcp_port)
    try:
        # Authenticate first
        await send_tcp_line(
            writer,
            {"type": "hello", "client_id": "training-client", "token": "dev-viewer-key"},
        )
        hello_reply = await read_tcp_line(reader)
        assert hello_reply.get("type") in ("hello", "welcome") or hello_reply.get("status") == "ok"

        # Ping -> Pong
        await send_tcp_line(writer, {"type": "ping", "request_id": "req-ch1"})
        pong_reply = await read_tcp_line(reader)
        assert pong_reply.get("type") == "pong"
        assert pong_reply.get("request_id") == "req-ch1"
    finally:
        writer.close()
        await writer.wait_closed()

    # 3. UDP beacon ack
    udp_reply = await roundtrip_udp(
        stack.udp_port,
        {
            "type": "beacon",
            "client_id": "training-client",
            "seq": 1,
            "token": "dev-viewer-key",
        },
    )
    assert udp_reply is not None
    assert udp_reply.get("type") in ("ack", "beacon_ack")
    assert udp_reply.get("seq") == 1
