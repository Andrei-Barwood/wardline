
import pytest
from httpx import AsyncClient
from tests.integration.conftest import open_tcp, read_tcp_line, roundtrip_udp, send_tcp_line


@pytest.mark.asyncio
async def test_tcp_line_too_large(stack):
    reader, writer = await open_tcp(stack.tcp_port)
    await send_tcp_line(writer, {"type": "hello", "client_id": "test", "token": "dev-admin-key"})
    resp = await read_tcp_line(reader)
    assert resp.get("type") == "welcome"
    
    large_line = b"x" * 4097 + b"\n"
    writer.write(large_line)
    await writer.drain()
    
    resp = await read_tcp_line(reader)
    assert resp.get("code") == "message_too_large"
    
    line = await reader.read()
    assert line == b""

@pytest.mark.asyncio
async def test_tcp_echo_too_large(stack):
    reader, writer = await open_tcp(stack.tcp_port)
    await send_tcp_line(writer, {"type": "hello", "client_id": "test", "token": "dev-admin-key"})
    await read_tcp_line(reader)
    
    await send_tcp_line(writer, {"type": "echo", "request_id": "1", "payload": "x" * 257})
    resp = await read_tcp_line(reader)
    assert resp.get("code") == "invalid_message"

@pytest.mark.asyncio
async def test_udp_too_large(stack):
    large_payload = b"x" * 2000
    resp = await roundtrip_udp(stack.udp_port, large_payload, timeout=0.2)
    assert resp is None

@pytest.mark.asyncio
async def test_admin_config_database_url(stack):
    async with AsyncClient(base_url=stack.base_url) as client:
        r = await client.post("/admin/config", headers={"Authorization": "Bearer dev-admin-key"}, json={"database_url": "postgres://..."}) # noqa: E501
        assert r.status_code == 400

@pytest.mark.asyncio
async def test_tcp_many_keys(stack):
    reader, writer = await open_tcp(stack.tcp_port)
    payload = {"type": "hello", "client_id": "test", "token": "dev-admin-key"}
    for i in range(25):
        payload[f"k{i}"] = "v"
    
    await send_tcp_line(writer, payload)
    resp = await read_tcp_line(reader)
    assert resp.get("code") == "invalid_message"
