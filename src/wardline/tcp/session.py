"""One accepted TCP connection. The payload of echo is returned as text."""

import asyncio
import re
import uuid
from typing import Any

from wardline.clients.identity import validate_client_id
from wardline.contracts import ErrorCode, Principal, Role, SecurityEvent, ServiceName, Severity
from wardline.errors import WardlineError
from wardline.monitoring.stats import TransportStats
from wardline.runtime import AppState
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
                if not self.state.circuit_breakers.allow(ServiceName.TCP):
                    self.stats.bump("messages_invalid")
                    await self._fail(ErrorCode.circuit_open, "circuit open", None, closing=True)
                    return
                try:
                    message = parse_line(raw, max_bytes=self.state.settings.tcp_max_message_bytes)
                except WardlineError as caught:
                    closing = (not welcomed) or self._note_error(caught.code)
                    await self._fail(caught.code, caught.message, None, closing=closing)
                    if closing:
                        return
                    continue
                if not welcomed:
                    if message.get("type") != "hello":
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
                if message.get("type") == "hello":
                    await self._fail(
                        ErrorCode.invalid_message,
                        "invalid message",
                        None,
                        closing=True,
                    )
                    return
                if not self._allow_rate():
                    closing = self._note_error(ErrorCode.rate_limited)
                    request_id = message.get("request_id")
                    await self._fail(
                        ErrorCode.rate_limited,
                        "rate limited",
                        request_id if isinstance(request_id, str) else None,
                        closing=closing,
                    )
                    if closing:
                        return
                    continue
                if not await self._dispatch(message):
                    return
        except WardlineError as caught:
            self.stats.bump("messages_invalid")
            if caught.code == ErrorCode.timeout:
                self.stats.bump("timeouts")
            await self._fail(caught.code, caught.message, None, closing=True)
        except (ConnectionError, asyncio.IncompleteReadError):
            return

    async def _hello(self, message: dict[str, Any]) -> str:
        """Return ok, again, or stop. again keeps the connection waiting for hello."""
        try:
            client_id = validate_client_id(message.get("client_id"))
        except WardlineError as caught:
            await self._fail(caught.code, caught.message, None, closing=True)
            return "stop"
        self.client_id = client_id
        if not self._allow_rate():
            closing = self._note_error(ErrorCode.rate_limited)
            await self._fail(ErrorCode.rate_limited, "rate limited", None, closing=closing)
            return "stop" if closing else "again"
        token = message.get("token")
        authenticated = self.state.auth.authenticate(token if isinstance(token, str) else None)
        role = authenticated.role if authenticated is not None else Role.VIEWER
        self.principal = Principal(client_id=client_id, role=role, authenticated=False)
        self.stats.bump("messages_valid")
        await self._send(
            {
                "type": "welcome",
                "client_id": client_id,
                "role": role.value,
                "session_id": self.session_id,
            }
        )
        return "ok"

    async def _dispatch(self, message: dict[str, Any]) -> bool:
        message_type = message.get("type")
        request_id = message.get("request_id")
        try:
            if message_type == "bye":
                self.stats.bump("messages_valid")
                await self._send({"type": "bye", "request_id": None})
                return False
            checked = _require_request_id(request_id)
            if message_type == "ping":
                payload: dict[str, Any] = {"type": "pong", "request_id": checked}
            elif message_type == "echo":
                echo_payload = message.get("payload")
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
            ErrorCode.unauthorized,
            ErrorCode.forbidden,
            ErrorCode.connection_limit,
        }
        if code not in audited:
            return
        self.state.audit.append(
            SecurityEvent(
                timestamp=self.state.clock.now(),
                source=self.client_id or "unknown",
                service=ServiceName.TCP,
                event_type=code.value,
                severity=Severity.LOW,
                simulation=False,
                action="recorded",
                correlation_id=self.session_id,
            )
        )

    def _allow_rate(self) -> bool:
        key = f"tcp:{self.client_id}" if self.client_id is not None else "tcp:pre-hello"
        return self.state.rate_limiter.allow(key)

    def _note_error(self, code: ErrorCode) -> bool:
        """Count a recoverable session error. Return True when the session must close."""
        self.stats.bump("messages_invalid")
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
