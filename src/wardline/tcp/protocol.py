"""Line-delimited JSON for the local TCP service. One object per line."""

import json
from collections.abc import Mapping
from typing import Any

from wardline.contracts import ErrorCode
from wardline.errors import WardlineError
from wardline.security.limits import check_message_size
from wardline.security.validation import TcpCommand, validate_tcp

ALLOWED_TYPES = frozenset({"hello", "ping", "echo", "status", "bye"})


def parse_line(raw: bytes, *, max_bytes: int) -> TcpCommand:
    """Parse one UTF-8 JSON object. Oversized input is rejected before decoding."""
    check_message_size(len(raw), max_bytes)
    stripped = raw[:-1] if raw.endswith(b"\n") else raw
    if stripped.endswith(b"\r"):
        stripped = stripped[:-1]
    try:
        text = stripped.decode("utf-8")
    except UnicodeDecodeError as caught:
        raise WardlineError(ErrorCode.invalid_message, "invalid message") from caught
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as caught:
        raise WardlineError(ErrorCode.invalid_message, "invalid message") from caught
    if not isinstance(parsed, dict):
        raise WardlineError(ErrorCode.invalid_message, "invalid message")
    return validate_tcp(parsed)


def encode(obj: Mapping[str, Any]) -> bytes:
    """Serialize one object as a single UTF-8 line."""
    return json.dumps(dict(obj), separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
