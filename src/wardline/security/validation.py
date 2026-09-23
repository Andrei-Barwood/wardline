import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from wardline.clients.identity import validate_client_id
from wardline.contracts import ErrorCode
from wardline.errors import WardlineError

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_MAX_KEYS = 20


@dataclass(frozen=True)
class Schema:
    required: set[str]
    optional: set[str]


TCP_SCHEMAS = {
    "hello": Schema(required={"client_id", "token"}, optional=set()),
    "ping": Schema(required={"request_id"}, optional=set()),
    "echo": Schema(required={"request_id", "payload"}, optional=set()),
    "status": Schema(required={"request_id"}, optional=set()),
    "bye": Schema(required=set(), optional=set()),
}

UDP_SCHEMAS = {
    "beacon": Schema(required={"client_id", "token", "seq"}, optional=set()),
    "ping": Schema(required={"client_id", "token", "seq", "request_id"}, optional=set()),
}


@dataclass(frozen=True)
class TcpCommand:
    type: str
    client_id: str | None = None
    token: str | None = None
    request_id: str | None = None
    payload: str | None = None


@dataclass(frozen=True)
class UdpCommand:
    type: str
    client_id: str | None = None
    token: str | None = None
    seq: int | None = None
    request_id: str | None = None


def _check_structure(
    message: Mapping[str, Any], is_http: bool = False, http_allowed: set[str] | None = None
) -> None:
    if len(message) > _MAX_KEYS:
        code = ErrorCode.validation_error if is_http else ErrorCode.invalid_message
        raise WardlineError(code, "invalid message")

    for key, value in message.items():
        if isinstance(value, (list, dict)):
            if is_http and key == "details" and isinstance(value, dict):
                continue
            code = ErrorCode.validation_error if is_http else ErrorCode.invalid_message
            raise WardlineError(code, "invalid message")
        if http_allowed is not None and key not in http_allowed:
            code = ErrorCode.validation_error if is_http else ErrorCode.invalid_message
            raise WardlineError(code, "invalid message")


def _validate_request_id(value: Any, is_http: bool = False) -> str:
    if not isinstance(value, str):
        code = ErrorCode.validation_error if is_http else ErrorCode.invalid_message
        raise WardlineError(code, "invalid message")
    if not _REQUEST_ID_RE.match(value):
        code = ErrorCode.validation_error if is_http else ErrorCode.invalid_message
        raise WardlineError(code, "invalid message")
    return value


def _validate_payload(value: Any, is_http: bool = False) -> str:
    if not isinstance(value, str):
        code = ErrorCode.validation_error if is_http else ErrorCode.invalid_message
        raise WardlineError(code, "invalid message")
    if len(value) > 256:
        code = ErrorCode.validation_error if is_http else ErrorCode.invalid_message
        raise WardlineError(code, "invalid message")
    return value


def _validate_token(value: Any, is_http: bool = False) -> str:
    if not isinstance(value, str):
        code = ErrorCode.validation_error if is_http else ErrorCode.invalid_message
        raise WardlineError(code, "invalid message")
    if not (1 <= len(value) <= 128):
        code = ErrorCode.validation_error if is_http else ErrorCode.invalid_message
        raise WardlineError(code, "invalid message")
    return value


def _validate_seq(value: Any, is_http: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        code = ErrorCode.validation_error if is_http else ErrorCode.invalid_message
        raise WardlineError(code, "invalid seq")
    if not (0 <= value <= 1_000_000_000):
        code = ErrorCode.validation_error if is_http else ErrorCode.invalid_message
        raise WardlineError(code, "invalid seq")
    return value


def validate_tcp(message: Mapping[str, Any]) -> TcpCommand:
    _check_structure(message)
    msg_type = message.get("type")
    if not isinstance(msg_type, str) or msg_type not in TCP_SCHEMAS:
        raise WardlineError(ErrorCode.invalid_message, "invalid message")

    schema = TCP_SCHEMAS[msg_type]

    for req in schema.required:
        if req not in message:
            raise WardlineError(ErrorCode.invalid_message, "invalid message")

    kwargs: dict[str, Any] = {"type": msg_type}
    allowed = schema.required | schema.optional

    for field in allowed:
        if field in message:
            val = message[field]
            if field == "client_id":
                kwargs[field] = validate_client_id(val)
            elif field == "token":
                kwargs[field] = _validate_token(val)
            elif field == "request_id":
                kwargs[field] = _validate_request_id(val)
            elif field == "payload":
                kwargs[field] = _validate_payload(val)

    return TcpCommand(**kwargs)


def validate_udp(message: Mapping[str, Any]) -> UdpCommand:
    _check_structure(message)
    msg_type = message.get("type")
    if not isinstance(msg_type, str) or msg_type not in UDP_SCHEMAS:
        raise WardlineError(ErrorCode.invalid_message, "invalid message")

    schema = UDP_SCHEMAS[msg_type]

    for req in schema.required:
        if req not in message:
            raise WardlineError(ErrorCode.invalid_message, "invalid message")

    kwargs: dict[str, Any] = {"type": msg_type}
    allowed = schema.required | schema.optional

    for field in allowed:
        if field in message:
            val = message[field]
            if field == "client_id":
                kwargs[field] = validate_client_id(val)
            elif field == "token":
                kwargs[field] = _validate_token(val)
            elif field == "request_id":
                kwargs[field] = _validate_request_id(val)
            elif field == "seq":
                kwargs[field] = _validate_seq(val)

    return UdpCommand(**kwargs)


def validate_admin_body(payload: Mapping[str, Any], *, allowed: set[str]) -> dict[str, Any]:
    _check_structure(payload, is_http=True, http_allowed=allowed)
    return dict(payload)
