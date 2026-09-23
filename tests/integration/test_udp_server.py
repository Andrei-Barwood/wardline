"""UDP on 127.0.0.1. Oversized datagrams get no reply."""

import asyncio
import json
from collections.abc import Callable

import httpx

from wardline.config.settings import Settings
from wardline.runtime import AppState, build_state
from wardline.serve import RunningServer, start_http, start_tcp, start_udp


class _Client(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.packets: asyncio.Queue[bytes] = asyncio.Queue()
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int] | tuple[object, ...]) -> None:
        del addr
        self.packets.put_nowait(data)


class _DenyLimiter:
    def allow(self, key: str, *, cost: int = 1) -> bool:
        del key, cost
        return False


async def _endpoint() -> tuple[asyncio.DatagramTransport, _Client]:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        _Client,
        local_addr=("127.0.0.1", 0),
    )
    assert isinstance(protocol, _Client)
    return transport, protocol


async def _started(settings: Settings) -> tuple[AppState, RunningServer]:
    state = build_state(settings)
    running = await start_udp(state)
    return state, running


def _beacon(seq: int = 1) -> bytes:
    return json.dumps(
        {"type": "beacon", "client_id": "training-client", "seq": seq},
        separators=(",", ":"),
    ).encode("utf-8")


async def _roundtrip(port: int, payload: bytes, timeout: float = 1.0) -> bytes:
    transport, protocol = await _endpoint()
    try:
        transport.sendto(payload, ("127.0.0.1", port))
        return await asyncio.wait_for(protocol.packets.get(), timeout)
    finally:
        transport.close()


async def test_udp_beacon_ack(settings_factory: Callable[..., Settings]) -> None:
    _state, running = await _started(settings_factory())
    try:
        raw = await _roundtrip(running.port, _beacon())
        assert len(raw) <= 200
        body = json.loads(raw)
        assert body["type"] == "beacon_ack"
        assert body["client_id"] == "training-client"
        assert body["seq"] == 1
        assert body["role"] == "viewer"
    finally:
        await running.stop()


async def test_udp_ping(settings_factory: Callable[..., Settings]) -> None:
    _state, running = await _started(settings_factory())
    try:
        payload = json.dumps(
            {"type": "ping", "client_id": "training-client", "seq": 2, "request_id": "u1"},
            separators=(",", ":"),
        ).encode("utf-8")
        body = json.loads(await _roundtrip(running.port, payload))
        assert body == {"type": "pong", "request_id": "u1", "seq": 2}
    finally:
        await running.stop()


async def test_udp_rejects_non_json_with_small_error(
    settings_factory: Callable[..., Settings],
) -> None:
    _state, running = await _started(settings_factory())
    try:
        raw = await _roundtrip(running.port, b"not-json")
        assert len(raw) <= 200
        body = json.loads(raw)
        assert body["type"] == "error"
        assert body["code"] == "invalid_message"
    finally:
        await running.stop()


async def test_udp_oversize_is_dropped_without_reply(
    settings_factory: Callable[..., Settings],
) -> None:
    state, running = await _started(settings_factory())
    transport, protocol = await _endpoint()
    try:
        transport.sendto(b"x" * 1100, ("127.0.0.1", running.port))
        await asyncio.wait_for(protocol.packets.get(), 0.3)
        raise AssertionError("oversized datagram received a reply")
    except TimeoutError:
        assert state.udp_stats.as_dict()["datagrams_dropped"] >= 1
    finally:
        transport.close()
        await running.stop()


async def test_udp_rate_limiter_double_drops(settings_factory: Callable[..., Settings]) -> None:
    state, running = await _started(settings_factory())
    state.rate_limiter = _DenyLimiter()  # type: ignore[assignment]
    transport, protocol = await _endpoint()
    try:
        transport.sendto(_beacon(), ("127.0.0.1", running.port))
        try:
            await asyncio.wait_for(protocol.packets.get(), 0.3)
            raise AssertionError("rate limited datagram received a reply")
        except TimeoutError:
            events = state.events.list_events()
            assert any(event.event_type == "security_rate_limited" for event in events)
    finally:
        transport.close()
        await running.stop()


async def test_health_ok_when_all_components_up(settings_factory: Callable[..., Settings]) -> None:
    state = build_state(settings_factory())
    http = await start_http(state)
    tcp = await start_tcp(state)
    udp = await start_udp(state)
    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{http.port}",
            timeout=2,
        ) as client:
            response = await client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["checks"] == {"http": "ok", "tcp": "ok", "udp": "ok", "database": "ok"}
    finally:
        await udp.stop()
        await tcp.stop()
        await http.stop()
