"""TCP sessions on 127.0.0.1 with an ephemeral port."""

import asyncio
import json
from collections.abc import Callable

import httpx

from wardline.audit.log import MemoryAuditLog
from wardline.config.settings import Settings
from wardline.contracts import ServiceName
from wardline.runtime import AppState, build_state
from wardline.serve import RunningServer, start_http, start_tcp
from wardline.tcp.server import TcpServer


class _DenyLimiter:
    def allow(self, key: str, *, cost: int = 1) -> bool:
        del key, cost
        return False


class _OpenCircuit:
    def allow(self, service: ServiceName) -> bool:
        del service
        return False

    def record_failure(self, service: ServiceName) -> None:
        del service


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


def _hello(
    client_id: str = "training-client",
    token: str = "dev-viewer-key",
) -> dict[str, object]:
    return {"type": "hello", "client_id": client_id, "token": token}


async def _started(settings: Settings) -> tuple[AppState, RunningServer]:
    state = build_state(settings)
    running = await start_tcp(state)
    return state, running


async def test_tcp_ping_pong(settings_factory: Callable[..., Settings]) -> None:
    _state, running = await _started(settings_factory())
    try:
        bound = running.server.sockets[0].getsockname()
        assert bound[0] == "127.0.0.1"
        reader, writer = await _open(running.port)
        await _send(writer, _hello())
        welcome = await _read(reader)
        assert welcome["type"] == "welcome"
        assert welcome["role"] == "viewer"
        assert welcome["client_id"] == "training-client"
        await _send(writer, {"type": "ping", "request_id": "p1"})
        assert await _read(reader) == {"type": "pong", "request_id": "p1"}
        writer.close()
        await writer.wait_closed()
    finally:
        await running.stop()


async def test_tcp_echo_roundtrip(settings_factory: Callable[..., Settings]) -> None:
    _state, running = await _started(settings_factory())
    try:
        reader, writer = await _open(running.port)
        await _send(writer, _hello())
        await _read(reader)
        nested = '{"type":"ping"}'
        await _send(writer, {"type": "echo", "request_id": "e1", "payload": nested})
        echoed = await _read(reader)
        assert echoed == {"type": "echo", "request_id": "e1", "payload": nested}
        writer.close()
        await writer.wait_closed()
    finally:
        await running.stop()


async def test_tcp_echo_rejects_long_payload(settings_factory: Callable[..., Settings]) -> None:
    _state, running = await _started(settings_factory())
    try:
        reader, writer = await _open(running.port)
        await _send(writer, _hello())
        await _read(reader)
        await _send(writer, {"type": "echo", "request_id": "e2", "payload": "x" * 257})
        error = await _read(reader)
        assert error["type"] == "error"
        assert error["code"] == "invalid_message"
        await _send(writer, {"type": "ping", "request_id": "still-open"})
        assert (await _read(reader))["type"] == "pong"
        writer.close()
        await writer.wait_closed()
    finally:
        await running.stop()


async def test_tcp_rejects_non_json_then_allows_next_until_error_budget(
    settings_factory: Callable[..., Settings],
) -> None:
    state, running = await _started(settings_factory(tcp_max_errors_per_session=2))
    try:
        reader, writer = await _open(running.port)
        await _send(writer, _hello())
        await _read(reader)
        writer.write(b"no-json\n")
        await writer.drain()
        assert (await _read(reader))["code"] == "invalid_message"
        await _send(writer, {"type": "ping", "request_id": "after-bad"})
        assert (await _read(reader))["type"] == "pong"
        writer.write(b"still-bad\n")
        await writer.drain()
        assert (await _read(reader))["code"] == "invalid_message"
        leftover = await asyncio.wait_for(reader.readline(), timeout=1)
        assert leftover == b""
        assert isinstance(running.server, TcpServer)
        assert state.tcp_stats.as_dict()["messages_invalid"] >= 2
    finally:
        await running.stop()


async def test_tcp_hello_required_first(settings_factory: Callable[..., Settings]) -> None:
    _state, running = await _started(settings_factory())
    try:
        reader, writer = await _open(running.port)
        await _send(writer, {"type": "ping", "request_id": "early"})
        error = await _read(reader)
        assert error["code"] == "invalid_message"
        writer.close()
        await writer.wait_closed()
    finally:
        await running.stop()


async def test_tcp_bye_closes(settings_factory: Callable[..., Settings]) -> None:
    _state, running = await _started(settings_factory())
    try:
        reader, writer = await _open(running.port)
        await _send(writer, _hello())
        await _read(reader)
        await _send(writer, {"type": "bye"})
        assert await _read(reader) == {"type": "bye", "request_id": None}
        assert await asyncio.wait_for(reader.readline(), timeout=1) == b""
    finally:
        await running.stop()


async def test_tcp_oversize_closes(settings_factory: Callable[..., Settings]) -> None:
    _state, running = await _started(settings_factory(tcp_max_message_bytes=128))
    try:
        reader, writer = await _open(running.port)
        writer.write(b"x" * 200)
        await writer.drain()
        error = await _read(reader)
        assert error["code"] == "message_too_large"
        assert await asyncio.wait_for(reader.readline(), timeout=1) == b""
    finally:
        await running.stop()


async def test_tcp_idle_timeout(settings_factory: Callable[..., Settings]) -> None:
    state = build_state(settings_factory())
    state.settings.tcp_idle_timeout_seconds = 0.2
    running = await start_tcp(state)
    try:
        reader, writer = await _open(running.port)
        error = await _read(reader, timeout=1.5)
        assert error["code"] == "timeout"
        assert state.tcp_stats.as_dict()["timeouts"] >= 1
        writer.close()
        await writer.wait_closed()
    finally:
        await running.stop()


async def test_tcp_connection_limit(settings_factory: Callable[..., Settings]) -> None:
    state, running = await _started(settings_factory(tcp_max_connections=2))
    first: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
    second: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
    third: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
    try:
        first = await _open(running.port)
        await _send(first[1], _hello("client-a"))
        await _read(first[0])
        second = await _open(running.port)
        await _send(second[1], _hello("client-b"))
        await _read(second[0])
        assert isinstance(running.server, TcpServer)
        assert running.server.active_connections == 2
        third = await _open(running.port)
        rejected = await _read(third[0])
        assert rejected["code"] == "connection_limit"
        assert running.server.active_connections <= 2
        assert state.tcp_stats.as_dict()["connections_rejected"] >= 1
    finally:
        for pair in (first, second, third):
            if pair is not None:
                pair[1].close()
                await pair[1].wait_closed()
        await running.stop()
        assert isinstance(running.server, TcpServer)
        assert running.server.active_connections == 0


async def test_tcp_rate_limiter_double_rejects(settings_factory: Callable[..., Settings]) -> None:
    state, running = await _started(settings_factory())
    state.rate_limiter = _DenyLimiter()  # type: ignore[assignment]
    try:
        reader, writer = await _open(running.port)
        await _send(writer, _hello())
        error = await _read(reader)
        assert error["code"] == "rate_limited"
        writer.close()
        await writer.wait_closed()
    finally:
        await running.stop()


async def test_tcp_circuit_open_closes(settings_factory: Callable[..., Settings]) -> None:
    state, running = await _started(settings_factory())
    state.circuit_breakers = _OpenCircuit()  # type: ignore[assignment]
    try:
        reader, writer = await _open(running.port)
        await _send(writer, _hello())
        error = await _read(reader)
        assert error["code"] == "circuit_open"
        assert await asyncio.wait_for(reader.readline(), timeout=1) == b""
        writer.close()
        await writer.wait_closed()
    finally:
        await running.stop()


async def test_status_binding_shows_effective_port(
    settings_factory: Callable[..., Settings],
) -> None:
    state = build_state(settings_factory())
    http = await start_http(state)
    tcp = await start_tcp(state)
    try:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{http.port}", timeout=2) as client:
            response = await client.get(
                "/status",
                headers={"Authorization": "Bearer dev-viewer-key"},
            )
        body = response.json()
        assert body["bindings"]["tcp"] == f"127.0.0.1:{tcp.port}"
        assert body["bindings"]["http"] == f"127.0.0.1:{http.port}"
        assert str(tcp.port) in body["bindings"]["tcp"]
    finally:
        await tcp.stop()
        await http.stop()


async def test_tcp_invalid_message_is_audited(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory()
    state = build_state(settings)
    audit = MemoryAuditLog(clock=state.clock)
    state.audit = audit
    running = await start_tcp(state)
    try:
        reader, writer = await _open(running.port)
        await _send(writer, _hello("audit-client"))
        welcome = await _read(reader)
        assert welcome["type"] == "welcome"

        writer.write(b"not-json\n")
        await writer.drain()

        err = await _read(reader)
        assert err["type"] == "error"
        assert err["code"] == "invalid_message"

        writer.close()
        await writer.wait_closed()

        events = [e for e in audit.events if e.event_type == "invalid_message"]
        assert len(events) >= 1
        assert events[0].source == "audit-client"
        assert events[0].service == ServiceName.TCP

        for ev in audit.events:
            assert "dev-admin-key" not in ev.model_dump_json()
    finally:
        await running.stop()

