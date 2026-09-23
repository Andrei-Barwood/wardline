"""Local TCP listener. It accepts connections only on the configured loopback host."""

import asyncio
import socket
import uuid

from wardline.contracts import ErrorCode, SecurityEvent, ServiceName, Severity
from wardline.errors import WardlineError
from wardline.runtime import AppState
from wardline.security.limits import check_connection_capacity
from wardline.tcp.protocol import encode
from wardline.tcp.session import TcpSession


class TcpServer:
    """asyncio server for the line protocol. One task serves each connection."""

    def __init__(self, state: AppState) -> None:
        self.state = state
        self._server: asyncio.Server | None = None
        self._active = 0
        self._tasks: set[asyncio.Task[None]] = set()
        self._port = state.settings.tcp_port

    @property
    def port(self) -> int:
        return self._port

    @property
    def active_connections(self) -> int:
        return self._active

    @property
    def sockets(self) -> tuple[object, ...]:
        if self._server is None or self._server.sockets is None:
            return ()
        return tuple(self._server.sockets)

    async def start(self) -> None:
        """Bind the loopback socket and mark the TCP component healthy."""
        if self._server is not None:
            return
        self._server = await asyncio.start_server(
            self._handle,
            host=self.state.settings.tcp_host,
            port=self.state.settings.tcp_port,
        )
        bound: list[socket.socket] = list(self._server.sockets or [])
        if not bound:
            raise RuntimeError("tcp server has no listening socket")
        self._port = int(bound[0].getsockname()[1])
        self.state.bindings["tcp"] = f"{self.state.settings.tcp_host}:{self._port}"
        self.state.health.set_status("tcp", "ok")

    async def stop(self) -> None:
        """Close the listener and every session. Calling stop twice is safe."""
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self.state.health.set_status("tcp", "down")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        current = asyncio.current_task()
        if current is not None:
            self._tasks.add(current)
        accepted = False
        try:
            try:
                check_connection_capacity(self._active, self.state.settings.tcp_max_connections)
            except WardlineError as caught:
                self.state.tcp_stats.bump("connections_rejected")
                _audit_tcp(self.state, caught.code, "unknown")
                await _write_error(writer, caught.code, caught.message)
                return
            self._active += 1
            accepted = True
            self.state.tcp_stats.bump("connections_accepted")
            self.state.tcp_stats.bump("connections_active")
            session = TcpSession(self.state, reader, writer, self.state.tcp_stats)
            await session.run()
        finally:
            if accepted:
                self._active = max(0, self._active - 1)
                current_active = self.state.tcp_stats.as_dict()["connections_active"]
                if current_active > 0:
                    self.state.tcp_stats.bump("connections_active", -1)
            if current is not None:
                self._tasks.discard(current)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                return


def _audit_tcp(state: AppState, code: ErrorCode, source: str) -> None:
    state.audit.append(
        SecurityEvent(
            timestamp=state.clock.now(),
            source=source,
            service=ServiceName.TCP,
            event_type=code.value,
            severity=Severity.LOW,
            simulation=False,
            action="recorded",
            correlation_id=str(uuid.uuid4()),
        )
    )


async def _write_error(writer: asyncio.StreamWriter, code: ErrorCode, message: str) -> None:
    payload = {"type": "error", "code": code.value, "message": message, "request_id": None}
    writer.write(encode(payload))
    try:
        await asyncio.wait_for(writer.drain(), timeout=2)
    except (TimeoutError, ConnectionError, OSError):
        return
