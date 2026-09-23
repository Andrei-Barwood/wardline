import pytest

from wardline.contracts import ErrorCode
from wardline.errors import WardlineError
from wardline.security.validation import (
    validate_admin_body,
    validate_tcp,
    validate_udp,
)


def test_tcp_echo_schema_strips_unknown_fields():
    msg = {
        "type": "echo",
        "request_id": "req-1",
        "payload": "hello",
        "extra": "ignored"
    }
    cmd = validate_tcp(msg)
    assert cmd.type == "echo"
    assert cmd.request_id == "req-1"
    assert cmd.payload == "hello"
    assert not hasattr(cmd, "extra")

def test_tcp_bool_is_not_accepted_as_number():
    msg = {
        "type": "beacon",
        "client_id": "client-1",
        "token": "secret",
        "seq": True
    }
    with pytest.raises(WardlineError) as exc:
        validate_udp(msg)
    assert exc.value.code == ErrorCode.invalid_message

def test_udp_seq_rejects_bool_and_string():
    msg = {
        "type": "beacon",
        "client_id": "client-1",
        "token": "secret",
        "seq": "123"
    }
    with pytest.raises(WardlineError) as exc:
        validate_udp(msg)
    assert exc.value.code == ErrorCode.invalid_message
    
    msg["seq"] = True
    with pytest.raises(WardlineError) as exc:
        validate_udp(msg)
    assert exc.value.code == ErrorCode.invalid_message

def test_nested_object_rejected():
    msg = {
        "type": "echo",
        "request_id": "req-1",
        "payload": {"nested": "value"}
    }
    with pytest.raises(WardlineError) as exc:
        validate_tcp(msg)
    assert exc.value.code == ErrorCode.invalid_message
    
    # But HTTP admin body allows details
    msg_http = {"details": {"nested": "value"}, "other": "ok"}
    res = validate_admin_body(msg_http, allowed={"details", "other"})
    assert res["details"] == {"nested": "value"}

def test_too_many_keys_rejected():
    msg = {"type": "echo", "request_id": "req-1", "payload": "hello"}
    for i in range(25):
        msg[f"key_{i}"] = "value"
    with pytest.raises(WardlineError) as exc:
        validate_tcp(msg)
    assert exc.value.code == ErrorCode.invalid_message

def test_request_id_alphabet():
    msg = {"type": "ping", "request_id": "req@bad"}
    with pytest.raises(WardlineError) as exc:
        validate_tcp(msg)
    assert exc.value.code == ErrorCode.invalid_message

def test_payload_length_256_ok_257_rejected():
    msg = {"type": "echo", "request_id": "req-1", "payload": "a" * 256}
    cmd = validate_tcp(msg)
    assert cmd.payload == "a" * 256
    
    msg["payload"] = "a" * 257
    with pytest.raises(WardlineError) as exc:
        validate_tcp(msg)
    assert exc.value.code == ErrorCode.invalid_message

def test_admin_body_rejects_unknown_key():
    msg = {"allowed_key": "val", "bad_key": "val"}
    with pytest.raises(WardlineError) as exc:
        validate_admin_body(msg, allowed={"allowed_key"})
    assert exc.value.code == ErrorCode.validation_error
