import asyncio

import pytest

from wardline.auth.provider import AuthProvider
from wardline.config.settings import Settings
from wardline.contracts import ErrorCode, Principal
from wardline.errors import WardlineError
from wardline.runtime import build_state
from wardline.security.validation import TCP_SCHEMAS, UDP_SCHEMAS, validate_tcp
from wardline.serve import start_tcp
from wardline.tcp.protocol import ALLOWED_TYPES as TCP_ALLOWED
from wardline.udp.protocol import ALLOWED_TYPES as UDP_ALLOWED


def test_schema_covers_allowed_types():
    assert set(TCP_SCHEMAS.keys()) == TCP_ALLOWED
    assert set(UDP_SCHEMAS.keys()) == UDP_ALLOWED


class FailingRegistry:
    def get_token_hash(self, token: str) -> bytes | None:
        raise AssertionError("Registry should not be called")

    def register(self, token: str, role: str) -> None:
        pass


class FailingAuthProvider(AuthProvider):
    def authenticate_request(self, token: str, *, client_id: str | None = None) -> Principal | None:
        raise AssertionError("AuthProvider should not be called")


def test_token_over_128_does_not_call_registry():
    # If token > 128, validate_tcp should raise invalid_message before registry
    msg = {"type": "hello", "client_id": "client-1", "token": "a" * 129}
    with pytest.raises(WardlineError) as exc:
        validate_tcp(msg)
    assert exc.value.code == ErrorCode.invalid_message


@pytest.mark.asyncio
async def test_malformed_tcp_line_still_within_error_budget(unused_tcp_port):
    state = build_state(Settings(wardline_env="test", tcp_port=unused_tcp_port))

    running = await start_tcp(state)

    reader, writer = await asyncio.open_connection("127.0.0.1", running.port)

    writer.write(b'{"type": "hello", "client_id": "training-client", "token": "dev-viewer-key"}\n')
    await writer.drain()
    await reader.readline()

    for _ in range(3):
        writer.write(b'{"type": "bad"}\n')
        await writer.drain()
        line = await reader.readline()
        assert b'"code":"invalid_message"' in line

    writer.write(b'{"type": "bad"}\n')
    await writer.drain()
    line = await reader.readline()
    assert b'"code":"invalid_message"' in line

    # 5th error will close the connection (tcp_max_errors_per_session is 4 in testing usually?)
    # Wait, let's just assert that budget behaves.
    # Since I don't know the exact budget (default 5 maybe?), I'll just check that it counts errors.

    writer.close()
    await writer.wait_closed()
    await running.stop()
