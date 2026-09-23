"""Local UDP listener. Each datagram is independent and replies stay under 200 bytes.

The server uses asyncio.DatagramProtocol: one loopback socket, no sessions, and the
event loop delivers each datagram to datagram_received.
"""

import asyncio
import uuid
from collections import OrderedDict
from typing import Any

from wardline.clients.identity import validate_client_id
from wardline.contracts import ErrorCode, SecurityEvent, ServiceName, Severity
from wardline.errors import WardlineError
from wardline.runtime import AppState
from wardline.udp.protocol import encode_small, parse_datagram

_LOCAL_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_SEQ_LIMIT = 1024


def accept_peer(state: AppState, host: str) -> bool:
    """Return whether a reply is allowed. Non-loopback peers are recorded and dropped."""
    if host in _LOCAL_HOSTS:
        return True
    state.udp_stats.bump("datagrams_dropped")
    state.events.add(
        SecurityEvent(
            timestamp=state.clock.now(),
            source="unknown",
            service=ServiceName.UDP,
            event_type="security_nonlocal_peer",
            severity=Severity.HIGH,
            simulation=False,
            action="dropped",
            correlation_id=str(uuid.uuid4()),
            details={"host": host},
        )
    )
    return False


class UdpServer:
    """Datagram endpoint bound only to the configured loopback host."""

    def __init__(self, state: AppState) -> None:
        self.state = state
        self._transport: asyncio.DatagramTransport | None = None
        self._port = state.settings.udp_port
        self._last_seq: OrderedDict[str, int] = OrderedDict()

    @property
    def port(self) -> int:
        return self._port

    async def start(self) -> None:
        """Bind the socket. A second start while already bound does nothing."""
        if self._transport is not None:
            return
        loop = asyncio.get_running_loop()
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self),
            local_addr=(self.state.settings.udp_host, self.state.settings.udp_port),
        )
        self._transport = transport
        sock = transport.get_extra_info("socket")
        self._port = int(sock.getsockname()[1])
        self.state.bindings["udp"] = f"{self.state.settings.udp_host}:{self._port}"
        self.state.health.set_status("udp", "ok")

    async def stop(self) -> None:
        """Close the socket. A second call is a no-op."""
        transport = self._transport
        self._transport = None
        if transport is not None:
            transport.close()
        self.state.health.set_status("udp", "down")

    def handle(self, data: bytes, addr: tuple[str, int] | tuple[Any, ...]) -> None:
        """Count one datagram and maybe send one small reply to the same peer."""
        self.state.udp_stats.bump("bytes_in", min(len(data), 65535))
        self.state.udp_stats.bump("datagrams_received")
        host = str(addr[0])
        if not accept_peer(self.state, host):
            return
        if len(data) > self.state.settings.udp_max_datagram_bytes:
            # Oversized datagrams are dropped with no reply, which avoids amplification.
            self.state.udp_stats.bump("datagrams_dropped")
            self._audit(ErrorCode.message_too_large, host)
            return
        if not self.state.circuit_breakers.allow(ServiceName.UDP):
            self.state.udp_stats.bump("datagrams_dropped")
            self._audit(ErrorCode.circuit_open, host)
            return
        try:
            message = parse_datagram(data, max_bytes=self.state.settings.udp_max_datagram_bytes)
            client_id = validate_client_id(message.client_id)
        except WardlineError as caught:
            self._audit(caught.code, host)
            self._reply_error(addr, caught.code, caught.message)
            return
        if not self.state.rate_limiter.allow(f"udp:{client_id}"):
            self.state.udp_stats.bump("datagrams_dropped")
            rate_event = SecurityEvent(
                timestamp=self.state.clock.now(),
                source=client_id,
                service=ServiceName.UDP,
                event_type="security_rate_limited",
                severity=Severity.LOW,
                simulation=False,
                action="dropped",
                correlation_id=str(uuid.uuid4()),
            )
            self.state.events.add(rate_event)
            self.state.audit.append(rate_event)
            return
        assert message.seq is not None
        self._note_seq(client_id, message.seq)
        token = message.token
        if not isinstance(token, str) or not token:
            self._audit_auth_failure(client_id, "missing")
            self._reply_error(addr, ErrorCode.unauthorized, "unauthorized")
            return
        principal = self.state.auth.authenticate_request(token, client_id=client_id)
        if principal is None or not principal.authenticated:
            self._audit_auth_failure(client_id, "mismatch")
            self._reply_error(addr, ErrorCode.unauthorized, "unauthorized")
            return
        role = principal.role
        if message.type == "beacon":
            reply: dict[str, Any] = {
                "type": "beacon_ack",
                "client_id": client_id,
                "seq": message.seq,
                "role": role.value,
            }
        else:
            request_id = message.request_id
            if not isinstance(request_id, str) or not request_id:
                self._audit(ErrorCode.invalid_message, client_id)
                self._reply_error(addr, ErrorCode.invalid_message, "invalid message")
                return
            reply = {"type": "pong", "request_id": request_id, "seq": message.seq}
        self._send(addr, reply)
        self.state.udp_stats.bump("datagrams_valid")

    def _audit(self, code: ErrorCode, source: str) -> None:
        self.state.audit.append(
            SecurityEvent(
                timestamp=self.state.clock.now(),
                source=source,
                service=ServiceName.UDP,
                event_type=code.value,
                severity=Severity.LOW,
                simulation=False,
                action="dropped",
                correlation_id=str(uuid.uuid4()),
            )
        )

    def _audit_auth_failure(self, source: str, reason: str) -> None:
        self.state.audit.append(
            SecurityEvent(
                timestamp=self.state.clock.now(),
                source=source,
                service=ServiceName.AUTH,
                event_type="security_auth_failure",
                severity=Severity.LOW,
                simulation=False,
                action="rejected",
                correlation_id=str(uuid.uuid4()),
                details={"reason": reason},
            )
        )

    def _note_seq(self, client_id: str, seq: int) -> None:
        previous = self._last_seq.get(client_id)
        self._last_seq[client_id] = seq
        self._last_seq.move_to_end(client_id)
        while len(self._last_seq) > _SEQ_LIMIT:
            self._last_seq.popitem(last=False)
        if previous is not None and seq < previous:
            self.state.events.add(
                SecurityEvent(
                    timestamp=self.state.clock.now(),
                    source=client_id,
                    service=ServiceName.UDP,
                    event_type="security_udp_seq_rewind",
                    severity=Severity.INFO,
                    simulation=False,
                    action="recorded",
                    correlation_id=str(uuid.uuid4()),
                )
            )

    def _reply_error(
        self,
        addr: tuple[str, int] | tuple[Any, ...],
        code: ErrorCode,
        message: str,
    ) -> None:
        if not self.state.rate_limiter.allow(f"udp-invalid:{addr[0]}"):
            self.state.udp_stats.bump("datagrams_dropped")
            return
        self._send(addr, {"type": "error", "code": code.value, "message": message})

    def _send(self, addr: tuple[str, int] | tuple[Any, ...], payload: dict[str, Any]) -> None:
        transport = self._transport
        if transport is None:
            return
        try:
            encoded = encode_small(payload)
        except WardlineError:
            self.state.udp_stats.bump("datagrams_dropped")
            return
        transport.sendto(encoded, addr)


class _UdpProtocol(asyncio.DatagramProtocol):
    """Adapter that forwards each datagram into UdpServer.handle."""

    def __init__(self, server: UdpServer) -> None:
        self._server = server

    def datagram_received(self, data: bytes, addr: tuple[str, int] | tuple[Any, ...]) -> None:
        self._server.handle(data, addr)
