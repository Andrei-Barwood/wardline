"""Local health gate and probes for incident resolution and recovery.

HTTP verification reads the in-process HealthRegistry directly rather than issuing
an HTTP loopback request, precisely to avoid single-thread event loop deadlocks.
TCP and UDP probes issue socket probes against localhost when services are bound
and a viewer key is available.
"""

import asyncio
import json
from typing import Any

from wardline.auth.api_keys import parse_dev_api_keys
from wardline.config.settings import LOOPBACK_HOSTS
from wardline.contracts import Role
from wardline.runtime import AppState

_TIMEOUT_SECONDS = 1.0


class _UdpProbeProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.packets: asyncio.Queue[bytes] = asyncio.Queue()
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        if isinstance(transport, asyncio.DatagramTransport):
            self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int] | tuple[object, ...]) -> None:
        del addr
        self.packets.put_nowait(data)


class LocalHealthGate:
    """Verifies local component health without accepting arbitrary remote hosts."""

    def __init__(self) -> None:
        pass

    async def _probe_tcp(self, state: AppState, viewer_key: str, port: int) -> bool:
        """Probe TCP service with hello, ping, bye."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(state.settings.tcp_host, port),
                timeout=_TIMEOUT_SECONDS,
            )
        except Exception:
            return False

        try:
            # 1. Hello
            hello = {
                "type": "hello",
                "client_id": "healthcheck",
                "token": viewer_key,
            }
            writer.write(json.dumps(hello).encode("utf-8") + b"\n")
            await asyncio.wait_for(writer.drain(), timeout=_TIMEOUT_SECONDS)
            welcome_line = await asyncio.wait_for(reader.readline(), timeout=_TIMEOUT_SECONDS)
            welcome = json.loads(welcome_line)
            if welcome.get("type") != "welcome":
                return False

            # 2. Ping
            ping = {"type": "ping", "request_id": "hc-1"}
            writer.write(json.dumps(ping).encode("utf-8") + b"\n")
            await asyncio.wait_for(writer.drain(), timeout=_TIMEOUT_SECONDS)
            pong_line = await asyncio.wait_for(reader.readline(), timeout=_TIMEOUT_SECONDS)
            pong = json.loads(pong_line)
            if pong.get("type") != "pong":
                return False

            # 3. Bye
            bye = {"type": "bye"}
            writer.write(json.dumps(bye).encode("utf-8") + b"\n")
            await asyncio.wait_for(writer.drain(), timeout=_TIMEOUT_SECONDS)
            await asyncio.wait_for(reader.readline(), timeout=_TIMEOUT_SECONDS)
            return True
        except Exception:
            return False
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _probe_udp(self, state: AppState, viewer_key: str, port: int) -> bool:
        """Probe UDP service with beacon."""
        loop = asyncio.get_running_loop()
        try:
            transport, protocol = await asyncio.wait_for(
                loop.create_datagram_endpoint(
                    _UdpProbeProtocol,
                    local_addr=("127.0.0.1", 0),
                ),
                timeout=_TIMEOUT_SECONDS,
            )
        except Exception:
            return False

        try:
            payload = json.dumps(
                {
                    "type": "beacon",
                    "client_id": "healthcheck",
                    "token": viewer_key,
                    "seq": 1,
                },
                separators=(",", ":"),
            ).encode("utf-8")
            transport.sendto(payload, (state.settings.udp_host, port))
            reply = await asyncio.wait_for(protocol.packets.get(), timeout=_TIMEOUT_SECONDS)
            parsed = json.loads(reply)
            return bool(isinstance(parsed, dict) and parsed.get("type") == "beacon_ack")
        except Exception:
            return False
        finally:
            transport.close()

    async def report(self, state: AppState) -> dict[str, Any]:
        """Report component health matching the /health JSON structure.

        HTTP verification reads the in-process HealthRegistry directly rather than issuing
        an HTTP loopback request, precisely to avoid single-thread event loop deadlocks.
        TCP and UDP probes issue socket probes against localhost when services are bound
        and a viewer key is available.
        """
        registry_checks = state.health.snapshot()

        checks: dict[str, str] = {
            "http": registry_checks.get("http", "down"),
            "database": registry_checks.get("database", "down"),
            "tcp": registry_checks.get("tcp", "down"),
            "udp": registry_checks.get("udp", "down"),
        }

        # Check database directly if possible
        try:
            state.events.list_events(limit=1)
            checks["database"] = "ok"
        except Exception:
            checks["database"] = "down"

        # Check loopback host enforcement
        if state.settings.tcp_host not in LOOPBACK_HOSTS:
            checks["tcp"] = "down"
        if state.settings.udp_host not in LOOPBACK_HOSTS:
            checks["udp"] = "down"
        if state.settings.http_host not in LOOPBACK_HOSTS:
            checks["http"] = "down"

        # Extract effective ports from bindings or settings
        tcp_port = state.settings.tcp_port
        udp_port = state.settings.udp_port
        if "tcp" in state.bindings:
            try:
                tcp_port = int(state.bindings["tcp"].split(":")[-1])
            except (ValueError, IndexError):
                pass
        if "udp" in state.bindings:
            try:
                udp_port = int(state.bindings["udp"].split(":")[-1])
            except (ValueError, IndexError):
                pass

        keys = parse_dev_api_keys(state.settings.dev_api_keys)
        viewer_key = keys.get(Role.VIEWER)

        # Network probes if viewer_key exists and ports are bound (> 0) and loopback
        if (
            viewer_key
            and tcp_port > 0
            and state.settings.tcp_host in LOOPBACK_HOSTS
            and registry_checks.get("tcp") == "ok"
        ):
            try:
                tcp_ok = await self._probe_tcp(state, viewer_key, tcp_port)
                checks["tcp"] = "ok" if tcp_ok else "down"
            except Exception:
                checks["tcp"] = "down"

        if (
            viewer_key
            and udp_port > 0
            and state.settings.udp_host in LOOPBACK_HOSTS
            and registry_checks.get("udp") == "ok"
        ):
            try:
                udp_ok = await self._probe_udp(state, viewer_key, udp_port)
                checks["udp"] = "ok" if udp_ok else "down"
            except Exception:
                checks["udp"] = "down"

        healthy = all(v == "ok" for v in checks.values())
        return {
            "status": "ok" if healthy else "degraded",
            "checks": checks,
        }

    async def check(self, state: AppState) -> bool:
        """Return True if report status is ok, False otherwise."""
        rep = await self.report(state)
        return rep.get("status") == "ok"
