"""Pytest fixtures and helpers for full stack integration testing."""

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from wardline.config.settings import Settings
from wardline.contracts import Role
from wardline.runtime import AppState, build_state
from wardline.serve import RunningServer, start_http, start_tcp, start_udp

_FAKE_KEYS = {
    Role.VIEWER: "dev-viewer-key",
    Role.OPERATOR: "dev-operator-key",
    Role.ADMIN: "dev-admin-key",
}


@dataclass
class Stack:
    """Live full stack running HTTP, TCP, and UDP on loopback with ephemeral ports."""

    state: AppState
    http_port: int
    tcp_port: int
    udp_port: int
    base_url: str
    http_server: RunningServer
    tcp_server: RunningServer
    udp_server: RunningServer

    async def close(self) -> None:
        """Stop all background servers and dispose database pools."""
        await self.http_server.stop()
        await self.tcp_server.stop()
        await self.udp_server.stop()
        if hasattr(self.state.events, "engine"):
            self.state.events.engine.dispose()
        if hasattr(self.state.incidents, "engine"):
            self.state.incidents.engine.dispose()


@pytest.fixture
async def stack(tmp_path: Path) -> AsyncIterator[Stack]:
    """Start the full live stack with ephemeral ports and an isolated SQLite db."""
    db_file = tmp_path / "wardline.db"
    settings = Settings(
        http_host="127.0.0.1",
        tcp_host="127.0.0.1",
        udp_host="127.0.0.1",
        http_port=0,
        tcp_port=0,
        udp_port=0,
        database_url=f"sqlite:///{db_file}",
        dev_api_keys="viewer:dev-viewer-key,operator:dev-operator-key,admin:dev-admin-key",
        rate_limit_requests_per_minute=60,
        rate_limit_burst=2,
    )

    state = build_state(settings)
    http_srv = await start_http(state)
    tcp_srv = await start_tcp(state)
    udp_srv = await start_udp(state)
    base_url = f"http://127.0.0.1:{http_srv.port}"

    instance = Stack(
        state=state,
        http_port=http_srv.port,
        tcp_port=tcp_srv.port,
        udp_port=udp_srv.port,
        base_url=base_url,
        http_server=http_srv,
        tcp_server=tcp_srv,
        udp_server=udp_srv,
    )
    try:
        yield instance
    finally:
        await instance.close()


async def open_tcp(port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to local TCP server."""
    return await asyncio.open_connection("127.0.0.1", port)


async def send_tcp_line(writer: asyncio.StreamWriter, message: dict[str, Any] | bytes) -> None:
    """Send a line to TCP server."""
    if isinstance(message, dict):
        line = json.dumps(message).encode("utf-8") + b"\n"
    elif isinstance(message, bytes):
        line = message if message.endswith(b"\n") else message + b"\n"
    else:
        line = str(message).encode("utf-8") + b"\n"
    writer.write(line)
    await writer.drain()


async def read_tcp_line(reader: asyncio.StreamReader, timeout: float = 2.0) -> dict[str, Any]:
    """Read a JSON line from TCP server."""
    line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    if not line:
        return {}
    return json.loads(line.decode("utf-8"))


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()

    def datagram_received(self, data: bytes, addr: tuple[str, int] | tuple[Any, ...]) -> None:
        del addr
        self.queue.put_nowait(data)


async def roundtrip_udp(
    port: int, payload: dict[str, Any] | bytes, *, timeout: float = 1.0
) -> dict[str, Any] | None:
    """Send a UDP datagram and optionally wait for a reply."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        _UdpProtocol,
        local_addr=("127.0.0.1", 0),
    )
    try:
        raw = json.dumps(payload).encode("utf-8") if isinstance(payload, dict) else payload
        transport.sendto(raw, ("127.0.0.1", port))
        try:
            resp = await asyncio.wait_for(protocol.queue.get(), timeout=timeout)
            return json.loads(resp.decode("utf-8"))
        except TimeoutError:
            return None
    finally:
        transport.close()
