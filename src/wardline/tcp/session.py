"""One accepted TCP connection. The payload of echo is returned as text."""

import asyncio
import re
import uuid
from typing import Any

from wardline.auth.policy import TCP_COMMAND_MIN_ROLE, role_allows
from wardline.clients.identity import validate_client_id
from wardline.contracts import ErrorCode, Principal, Role, SecurityEvent, ServiceName, Severity
from wardline.errors import WardlineError
from wardline.monitoring.stats import TransportStats
from wardline.runtime import AppState
from wardline.security.validation import TcpCommand
from wardline.tcp.protocol import encode, parse_line

_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CLOSING_CODES = frozenset(
    {
        ErrorCode.message_too_large,
        ErrorCode.timeout,
        ErrorCode.circuit_open,
        ErrorCode.client_blocked,
        ErrorCode.unauthorized,
    }
)


class TcpSession:
    """Read newline-delimited requests and write one JSON response per line."""

    def __init__(
        self,
        state: AppState,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        stats: TransportStats,
    ) -> None:
        self.state = state
        self.reader = reader
        self.writer = writer
        self.stats = stats
        self.client_id: str | None = None
        self.principal: Principal | None = None
        self.session_id = str(uuid.uuid4())
        self._errors = 0

    async def run(self) -> None:
        """Serve the connection until it closes or a closing error is sent."""
        welcomed = False
        try:
            while not self.writer.is_closing():
                raw = await self._read_line()
                if raw is None:
                    return
                self.stats.bump("bytes_in", len(raw))
                try:
                    message = parse_line(raw, max_bytes=self.state.settings.tcp_max_message_bytes)
                except WardlineError as caught:
                    closing = (not welcomed) or self._note_error(caught.code)
                    await self._fail(caught.code, caught.message, None, closing=closing)
                    if closing:
                        return
                    continue
                if not welcomed:
                    if message.type != "hello":
                        await self._fail(
                            ErrorCode.invalid_message,
                            "invalid message",
                            None,
                            closing=True,
                        )
                        return
                    outcome = await self._hello(message)
                    if outcome == "stop":
                        return
                    if outcome == "ok":
                        welcomed = True
                    continue
                if message.type == "hello":
                    await self._fail(
                        ErrorCode.invalid_message,
                        "invalid message",
                        None,
                        closing=True,
                    )
                    return
                if not self.state.circuit_breakers.allow(ServiceName.TCP):
                    closing = self._note_error(ErrorCode.circuit_open)
                    request_id = message.request_id
                    await self._fail(
                        ErrorCode.circuit_open,
                        "circuit open",
                        request_id if isinstance(request_id, str) else None,
                        closing=closing,
                    )
                    if closing:
                        return
                    continue
                if not self._allow_rate():
                    closing = self._note_error(ErrorCode.rate_limited)
                    request_id = message.request_id
                    await self._fail(
                        ErrorCode.rate_limited,
                        "rate limited",
                        request_id if isinstance(request_id, str) else None,
                        closing=closing,
                    )
                    if closing:
                        return
                    continue
                assert self.client_id is not None
                if not self.state.quotas.allow(self.client_id):
                    closing = self._note_error(ErrorCode.quota_exceeded)
                    request_id = message.request_id
                    await self._fail(
                        ErrorCode.quota_exceeded,
                        "quota exceeded",
                        request_id if isinstance(request_id, str) else None,
                        closing=closing,
                    )
                    if closing:
                        return
                    continue
                if not await self._dispatch(message):
                    return
                from wardline.security.circuit_breaker import note_success

                note_success(self.state, ServiceName.TCP)
        except WardlineError as caught:
            self.stats.bump("messages_invalid")
            if caught.code == ErrorCode.timeout:
                self.stats.bump("timeouts")
            if caught.code in {
                ErrorCode.invalid_message,
                ErrorCode.message_too_large,
                ErrorCode.timeout,
                ErrorCode.rate_limited,
                ErrorCode.quota_exceeded,
                ErrorCode.connection_limit,
            }:
                from wardline.security.circuit_breaker import note_failure

                note_failure(self.state, ServiceName.TCP)
            await self._fail(caught.code, caught.message, None, closing=True)
        except (ConnectionError, asyncio.IncompleteReadError):
            return

    async def _hello(self, message: "TcpCommand") -> str:
        """Return ok, again, or stop. again keeps the connection waiting for hello."""
        try:
            client_id = validate_client_id(message.client_id)
        except WardlineError as caught:
            await self._fail(caught.code, caught.message, None, closing=True)
            return "stop"

        ip = self.writer.get_extra_info("peername")[0]

        token = message.token
        if not isinstance(token, str) or not token:
            self.state.rate_limiter.allow(f"tcp-unauth:{ip}")
            self.state.audit.append(
                SecurityEvent(
                    timestamp=self.state.clock.now(),
                    source=client_id,
                    service=ServiceName.AUTH,
                    event_type="security_auth_failure",
                    severity=Severity.LOW,
                    simulation=False,
                    action="rejected",
                    correlation_id=self.session_id,
                    details={"reason": "missing"},
                )
            )
            await self._fail(ErrorCode.invalid_message, "invalid message", None, closing=True)
            return "stop"

        principal = self.state.auth.authenticate_request(token, client_id=client_id)
        if principal is None or not principal.authenticated:
            self.state.rate_limiter.allow(f"tcp-unauth:{ip}")
            self.state.audit.append(
                SecurityEvent(
                    timestamp=self.state.clock.now(),
                    source=client_id,
                    service=ServiceName.AUTH,
                    event_type="security_auth_failure",
                    severity=Severity.LOW,
                    simulation=False,
                    action="rejected",
                    correlation_id=self.session_id,
                    details={"reason": "mismatch"},
                )
            )
            await self._fail(ErrorCode.unauthorized, "unauthorized", None, closing=True)
            return "stop"

        if not self.state.circuit_breakers.allow(ServiceName.TCP):
            closing = self._note_error(ErrorCode.circuit_open)
            await self._fail(ErrorCode.circuit_open, "circuit open", None, closing=closing)
            return "stop" if closing else "again"

        if not self.state.rate_limiter.allow(f"tcp:{client_id}"):
            closing = self._note_error(ErrorCode.rate_limited)
            await self._fail(ErrorCode.rate_limited, "rate limited", None, closing=closing)
            return "stop" if closing else "again"

        if not self.state.quotas.allow(client_id):
            closing = self._note_error(ErrorCode.quota_exceeded)
            await self._fail(ErrorCode.quota_exceeded, "quota exceeded", None, closing=closing)
            return "stop" if closing else "again"

        self.client_id = client_id
        self.principal = principal
        self.stats.bump("messages_valid")
        await self._send(
            {
                "type": "welcome",
                "client_id": client_id,
                "role": principal.role.value,
                "session_id": self.session_id,
            }
        )
        from wardline.security.circuit_breaker import note_success

        note_success(self.state, ServiceName.TCP)
        return "ok"

    async def _dispatch(self, message: "TcpCommand") -> bool:
        message_type = message.type
        request_id = message.request_id
        if isinstance(message_type, str):
            required_role = TCP_COMMAND_MIN_ROLE.get(message_type, Role.ADMIN)
            actual_role = self.principal.role if self.principal is not None else Role.VIEWER
            if not role_allows(actual_role, required_role):
                self.state.audit.append(
                    SecurityEvent(
                        timestamp=self.state.clock.now(),
                        source=self.client_id or "unknown",
                        service=ServiceName.AUTH,
                        event_type="security_authz_denied",
                        severity=Severity.LOW,
                        simulation=False,
                        action="denied",
                        correlation_id=self.session_id,
                        details={"required": required_role.value},
                    )
                )
                closing = self._note_error(ErrorCode.forbidden)
                visible_id = request_id if isinstance(request_id, str) else None
                await self._fail(ErrorCode.forbidden, "forbidden", visible_id, closing=closing)
                return not closing
        try:
            if message_type == "bye":
                self.stats.bump("messages_valid")
                await self._send({"type": "bye", "request_id": None})
                return False
            checked = _require_request_id(request_id)
            if message_type == "ping":
                payload: dict[str, Any] = {"type": "pong", "request_id": checked}
            elif message_type == "echo":
                echo_payload = message.payload
                if not isinstance(echo_payload, str) or len(echo_payload) > 256:
                    raise WardlineError(ErrorCode.invalid_message, "invalid message")
                payload = {"type": "echo", "request_id": checked, "payload": echo_payload}
            elif message_type == "status":
                if self.principal is not None:
                    role = self.principal.role.value
                else:
                    role = Role.VIEWER.value
                payload = {
                    "type": "status",
                    "request_id": checked,
                    "session_id": self.session_id,
                    "role": role,
                }
            else:
                raise WardlineError(ErrorCode.invalid_message, "invalid message")
        except WardlineError as caught:
            closing = self._note_error(caught.code)
            visible_id = request_id if isinstance(request_id, str) else None
            await self._fail(caught.code, caught.message, visible_id, closing=closing)
            return not closing
        self.stats.bump("messages_valid")
        await self._send(payload)
        return True

    def _audit(self, code: ErrorCode) -> None:
        audited = {
            ErrorCode.invalid_message,
            ErrorCode.message_too_large,
            ErrorCode.timeout,
            ErrorCode.rate_limited,
            ErrorCode.circuit_open,
            ErrorCode.client_blocked,
            ErrorCode.connection_limit,
        }
        if code not in audited and code != ErrorCode.quota_exceeded:
            return
        severity = Severity.MEDIUM if code == ErrorCode.quota_exceeded else Severity.LOW
        action = "rejected" if code == ErrorCode.quota_exceeded else "recorded"
        event_type = "security_quota_exceeded" if code == ErrorCode.quota_exceeded else code.value
        self.state.audit.append(
            SecurityEvent(
                timestamp=self.state.clock.now(),
                source=self.client_id or "unknown",
                service=ServiceName.TCP,
                event_type=event_type,
                severity=severity,
                simulation=False,
                action=action,
                correlation_id=self.session_id,
            )
        )

    def _allow_rate(self) -> bool:
        if self.client_id is None:
            return True
        key = f"tcp:{self.client_id}"
        return self.state.rate_limiter.allow(key)

    def _note_error(self, code: ErrorCode) -> bool:
        """Count a recoverable session error. Return True when the session must close."""
        self.stats.bump("messages_invalid")
        if code in {
            ErrorCode.invalid_message,
            ErrorCode.message_too_large,
            ErrorCode.timeout,
            ErrorCode.rate_limited,
            ErrorCode.quota_exceeded,
            ErrorCode.connection_limit,
        }:
            from wardline.security.circuit_breaker import note_failure

            note_failure(self.state, ServiceName.TCP)
        if code in _CLOSING_CODES:
            return True
        self._errors += 1
        return self._errors >= self.state.settings.tcp_max_errors_per_session

    async def _fail(
        self,
        code: ErrorCode,
        message: str,
        request_id: str | None,
        *,
        closing: bool,
    ) -> None:
        del closing
        self._audit(code)
        await self._send(
            {
                "type": "error",
                "code": code.value,
                "message": message,
                "request_id": request_id,
            }
        )

    async def _send(self, obj: dict[str, Any]) -> None:
        if self.writer.is_closing():
            return
        self.writer.write(encode(obj))
        try:
            await asyncio.wait_for(self.writer.drain(), timeout=2)
        except (TimeoutError, ConnectionError, OSError):
            return

    async def _read_line(self) -> bytes | None:
        limit = self.state.settings.tcp_max_message_bytes
        idle = self.state.settings.tcp_idle_timeout_seconds
        read_timeout = self.state.settings.tcp_read_timeout_seconds
        loop = asyncio.get_running_loop()
        deadline = loop.time() + idle
        buffer = bytearray()
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise WardlineError(ErrorCode.timeout, "timeout")
            try:
                chunk = await asyncio.wait_for(
                    self.reader.read(min(256, limit + 1 - len(buffer))),
                    timeout=min(remaining, read_timeout),
                )
            except TimeoutError as caught:
                raise WardlineError(ErrorCode.timeout, "timeout") from caught
            if not chunk:
                if buffer:
                    raise WardlineError(ErrorCode.invalid_message, "invalid message")
                return None
            buffer.extend(chunk)
            newline = buffer.find(b"\n")
            if newline != -1:
                line = bytes(buffer[: newline + 1])
                check_size(line, limit)
                return line
            if len(buffer) > limit:
                raise WardlineError(ErrorCode.message_too_large, "message too large")


def check_size(line: bytes, limit: int) -> None:
    if len(line) > limit:
        raise WardlineError(ErrorCode.message_too_large, "message too large")


def _require_request_id(value: object) -> str:
    if not isinstance(value, str) or _REQUEST_ID.fullmatch(value) is None:
        raise WardlineError(ErrorCode.invalid_message, "invalid message")
    return value
