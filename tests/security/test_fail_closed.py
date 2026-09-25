from datetime import UTC

import pytest
from httpx import AsyncClient
from tests.integration.conftest import open_tcp, read_tcp_line, send_tcp_line


@pytest.mark.asyncio
async def test_fail_closed_empty_keys(stack):
    from wardline.auth.provider import ApiKeyAuthProvider
    stack.state.auth = ApiKeyAuthProvider("")
    
    async with AsyncClient(base_url=stack.base_url) as client:
        r = await client.get("/status", headers={"Authorization": "Bearer dev-admin-key"})
        assert r.status_code == 401
        
    reader, writer = await open_tcp(stack.tcp_port)
    await send_tcp_line(writer, {"type": "hello", "client_id": "test", "token": "dev-admin-key"})
    resp = await read_tcp_line(reader)
    assert resp.get("code") == "unauthorized"
    
    line = await reader.read()
    assert line == b""

@pytest.mark.asyncio
async def test_detector_fail_keeps_event(stack):
    from datetime import datetime

    from wardline.contracts import SecurityEvent, ServiceName, Severity
    from wardline.security.events import record_event
    
    event = SecurityEvent(
        timestamp=datetime.now(UTC),
        source="test_client",
        service=ServiceName.HTTP,
        event_type="test_event",
        severity=Severity.LOW,
        simulation=False,
        action="recorded",
        correlation_id="uuid",
        details={}
    )
    
    original_observe = stack.state.anomaly.observe
    
    def failing_observe(*args, **kwargs):
        raise ValueError("Detector exploded!")
        
    stack.state.anomaly.observe = failing_observe
    
    record_event(stack.state, event)
        
    events = stack.state.events.list_events()
    assert any(e.correlation_id == "uuid" for e in events)
    stack.state.anomaly.observe = original_observe
