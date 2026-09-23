"""UDP datagram parsing and the small-reply limit."""

from collections.abc import Callable

import pytest

from wardline.config.settings import Settings
from wardline.contracts import ErrorCode, Severity
from wardline.errors import WardlineError
from wardline.runtime import build_state
from wardline.udp.protocol import encode_small, parse_datagram
from wardline.udp.server import accept_peer


def test_parse_beacon() -> None:
    message = parse_datagram(
        b'{"type":"beacon","client_id":"training-client","token":"secret","seq":1}',
        max_bytes=1024,
    )
    assert message.type == "beacon"
    assert message.seq == 1


def test_parse_rejects_oversize() -> None:
    raw = b'{"type":"beacon","token":"secret","seq":1}' + (b" " * 1100)
    with pytest.raises(WardlineError) as caught:
        parse_datagram(raw, max_bytes=1024)
    assert caught.value.code == ErrorCode.message_too_large


def test_encode_small_refuses_large_object() -> None:
    with pytest.raises(WardlineError) as caught:
        encode_small({"type": "beacon_ack", "client_id": "x" * 300, "seq": 1, "role": "viewer"})
    assert caught.value.code == ErrorCode.message_too_large


def test_seq_must_be_non_negative_int() -> None:
    parsed = parse_datagram(
        b'{"type":"beacon","client_id":"a","token":"secret","seq":0}', max_bytes=1024
    )
    assert parsed.seq == 0
    for raw in (
        b'{"type":"beacon","client_id":"a","seq":-1}',
        b'{"type":"beacon","client_id":"a","seq":true}',
        b'{"type":"beacon","client_id":"a","seq":"1"}',
    ):
        with pytest.raises(WardlineError) as caught:
            parse_datagram(raw, max_bytes=1024)
        assert caught.value.code == ErrorCode.invalid_message


def test_nonlocal_peer_is_dropped_and_recorded(
    settings_factory: Callable[..., Settings],
) -> None:
    state = build_state(settings_factory())
    assert accept_peer(state, "203.0.113.5") is False
    events = state.events.list_events()
    assert events[0].event_type == "security_nonlocal_peer"
    assert events[0].severity == Severity.HIGH
    assert events[0].simulation is False
    assert state.udp_stats.as_dict()["datagrams_dropped"] == 1
    assert accept_peer(state, "127.0.0.1") is True
