"""One JSON object per UDP datagram. Replies stay small so they cannot amplify."""

import json
from collections.abc import Mapping
from typing import Any

from wardline.contracts import ErrorCode
from wardline.errors import WardlineError
from wardline.security.limits import check_message_size
from wardline.security.validation import UdpCommand, validate_udp

ALLOWED_TYPES = frozenset({"beacon", "ping"})
_MAX_SEQ = 1_000_000_000


def parse_datagram(raw: bytes, *, max_bytes: int) -> UdpCommand:
    """Parse one datagram. Oversized input is rejected before JSON decoding."""
    check_message_size(len(raw), max_bytes)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as caught:
        raise WardlineError(ErrorCode.invalid_message, "invalid message") from caught
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as caught:
        raise WardlineError(ErrorCode.invalid_message, "invalid message") from caught
    if not isinstance(parsed, dict):
        raise WardlineError(ErrorCode.invalid_message, "invalid message")
    return validate_udp(parsed)


def encode_small(obj: Mapping[str, Any], *, max_bytes: int = 200) -> bytes:
    """Serialize a reply and refuse anything larger than max_bytes."""
    encoded = json.dumps(dict(obj), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > max_bytes:
        raise WardlineError(ErrorCode.message_too_large, "message too large")
    return encoded
