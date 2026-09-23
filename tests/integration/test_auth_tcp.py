"""TCP and UDP authentication tests."""

import asyncio
import json
from collections.abc import Callable

from wardline.config.settings import Settings
from wardline.runtime import build_state
from wardline.serve import start_tcp, start_udp


async def _open_tcp(port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection("127.0.0.1", port)


async def _send_line(writer: asyncio.StreamWriter, payload: dict[str, object]) -> None:
    writer.write(json.dumps(payload).encode("utf-8") + b"\n")
    await writer.drain()


async def _read_line(reader: asyncio.StreamReader, timeout: float = 1.0) -> dict[str, object]:
    line = await asyncio.wait_for(reader.readline(), timeout)
    assert line
    parsed = json.loads(line)
    assert isinstance(parsed, dict)
    return parsed


async def test_tcp_hello_without_token_closes(
    settings_factory: Callable[..., Settings],
) -> None:
    state = build_state(settings_factory())
    running = await start_tcp(state)
    try:
        reader, writer = await _open_tcp(running.port)
        await _send_line(writer, {"type": "hello", "client_id": "training-client"})
        response = await _read_line(reader)
        assert response["type"] == "error"
        assert response["code"] == "unauthorized"

        # Connection closes after unauthorized error
        closed = await asyncio.wait_for(reader.readline(), timeout=1.0)
        assert closed == b""
        writer.close()
        await writer.wait_closed()
    finally:
        await running.stop()


async def test_tcp_hello_with_admin_key_gets_admin_role(
    settings_factory: Callable[..., Settings],
) -> None:
    state = build_state(settings_factory())
    running = await start_tcp(state)
    try:
        reader, writer = await _open_tcp(running.port)
        await _send_line(
            writer,
            {"type": "hello", "client_id": "admin-client", "token": "dev-admin-key"},
        )
        response = await _read_line(reader)
        assert response["type"] == "welcome"
        assert response["client_id"] == "admin-client"
        assert response["role"] == "admin"
        assert "session_id" in response

        writer.close()
        await writer.wait_closed()
    finally:
        await running.stop()


class _UdpClient(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.packets: asyncio.Queue[bytes] = asyncio.Queue()
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int] | tuple[object, ...]) -> None:
        del addr
        self.packets.put_nowait(data)


async def test_udp_without_token_does_not_ack(
    settings_factory: Callable[..., Settings],
) -> None:
    state = build_state(settings_factory())
    running = await start_udp(state)
    try:
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            _UdpClient,
            local_addr=("127.0.0.1", 0),
        )
        assert isinstance(protocol, _UdpClient)
        try:
            # Datagram without token
            payload = json.dumps(
                {"type": "beacon", "client_id": "training-client", "seq": 1},
                separators=(",", ":"),
            ).encode("utf-8")
            transport.sendto(payload, ("127.0.0.1", running.port))

            raw_reply = await asyncio.wait_for(protocol.packets.get(), timeout=1.0)
            reply = json.loads(raw_reply)
            # Must NOT be beacon_ack; it returns unauthorized error
            assert reply["type"] == "error"
            assert reply["code"] == "unauthorized"
        finally:
            transport.close()
    finally:
        await running.stop()
