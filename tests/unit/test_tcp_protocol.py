"""TCP line parsing and client id rules."""

import pytest

from wardline.clients.identity import validate_client_id
from wardline.contracts import ErrorCode
from wardline.errors import WardlineError
from wardline.tcp.protocol import encode, parse_line


def test_parse_ping() -> None:
    message = parse_line(b'{"type":"ping","request_id":"abc"}\n', max_bytes=4096)
    assert message["type"] == "ping"
    assert message["request_id"] == "abc"


def test_parse_rejects_non_object() -> None:
    with pytest.raises(WardlineError) as caught:
        parse_line(b"[1, 2]\n", max_bytes=4096)
    assert caught.value.code == ErrorCode.invalid_message


def test_parse_rejects_unknown_type() -> None:
    with pytest.raises(WardlineError) as caught:
        parse_line(b'{"type":"exec"}\n', max_bytes=4096)
    assert caught.value.code == ErrorCode.invalid_message


def test_parse_rejects_oversize_before_json() -> None:
    raw = b'{"type":"ping"}' + (b" " * 5000) + b"\n"
    with pytest.raises(WardlineError) as caught:
        parse_line(raw, max_bytes=128)
    assert caught.value.code == ErrorCode.message_too_large


def test_encode_appends_newline() -> None:
    encoded = encode({"type": "ping", "request_id": "abc"})
    assert encoded.endswith(b"\n")
    assert encoded.count(b"\n") == 1


def test_client_id_regex() -> None:
    assert validate_client_id("training-client") == "training-client"
    with pytest.raises(WardlineError) as caught:
        validate_client_id("Not-Valid")
    assert caught.value.code == ErrorCode.invalid_message
    with pytest.raises(WardlineError):
        validate_client_id("a" * 65)
