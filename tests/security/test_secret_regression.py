import os
from pathlib import Path

import pytest
from httpx import AsyncClient
from tests.integration.conftest import open_tcp, read_tcp_line, send_tcp_line


def test_secrets_not_in_source():
    src_dir = Path("src")
    forbidden = ["dev-viewer-key", "dev-operator-key", "dev-admin-key", "BEGIN PRIVATE KEY"]
    for root, _, files in os.walk(src_dir):
        for file in files:
            if file.endswith(".py"):
                content = (Path(root) / file).read_text(errors="ignore")
                for f in forbidden:
                    assert f not in content

@pytest.mark.asyncio
async def test_secrets_not_in_logs(stack):
    reader, writer = await open_tcp(stack.tcp_port)
    await send_tcp_line(writer, {"type": "hello", "client_id": "test1", "token": "dev-admin-key"})
    await read_tcp_line(reader)
    
    reader2, writer2 = await open_tcp(stack.tcp_port)
    await send_tcp_line(writer2, {"type": "hello", "client_id": "test2", "token": "super-secret-token"}) # noqa: E501
    await read_tcp_line(reader2)
    
    log_dir = Path("data/audit")
    if log_dir.exists():
        for file in log_dir.glob("*.jsonl"):
            content = file.read_text()
            assert "dev-admin-key" not in content
            assert "super-secret-token" not in content

@pytest.mark.asyncio
async def test_401_no_echo(stack):
    async with AsyncClient(base_url=stack.base_url) as client:
        r = await client.get("/status", headers={"Authorization": "Bearer super-secret-token"})
        assert r.status_code == 401
        assert "super-secret-token" not in r.text
        
        r2 = await client.get("/status", headers={"Authorization": "Bearer dev-admin-key"})
        assert r2.status_code == 200
        assert "dev-admin-key" not in r2.text
