import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient

from wardline.contracts import IncidentState, ServiceName, Severity
from wardline.incidents.models import Incident

MATRIX = [
    ("GET", "/health", 200, 200, 200, 200),
    ("GET", "/version", 200, 200, 200, 200),
    ("GET", "/status", 401, 200, 200, 200),
    ("GET", "/metrics", 401, 200, 200, 200),
    ("GET", "/events", 401, 200, 200, 200),
    ("GET", "/alerts", 401, 200, 200, 200),
    ("GET", "/security/summary", 401, 200, 200, 200),
    ("GET", "/incidents", 401, 200, 200, 200),
    ("GET", "/incidents/{incident_id}", 401, 200, 200, 200),
    ("GET", "/missions", 401, 200, 200, 200),
    ("GET", "/missions/m01", 401, 200, 200, 200),
    ("POST", "/incidents/{incident_id}/acknowledge", 401, 403, 200, 200),
    ("POST", "/simulation/run", 401, 403, 200, 200),
    ("POST", "/missions/m01/check", 401, 403, 200, 200),
    ("POST", "/incidents/{incident_id}/contain", 401, 403, 403, 200),
    ("POST", "/incidents/{incident_id}/resolve", 401, 403, 403, 200),
    ("POST", "/admin/config", 401, 403, 403, 200),
    ("POST", "/admin/recovery/rollback", 401, 403, 403, 409), 
    ("GET", "/admin/config", 401, 403, 403, 200),
    ("POST", "/admin/clients/some-client/block", 401, 403, 403, 200),
    ("POST", "/admin/clients/some-client/unblock", 401, 403, 403, 404),
]

def get_headers(role):
    if role is None:
        return {}
    return {"Authorization": f"Bearer dev-{role}-key"}

@pytest.mark.asyncio
@pytest.mark.parametrize("method, path, anon_status, viewer_status, operator_status, admin_status", MATRIX) # noqa: E501
async def test_authz_matrix(stack, method, path, anon_status, viewer_status, operator_status, admin_status): # noqa: E501
    def get_kwargs(m, p):
        payload = None
        if m == "POST":
            if "simulation" in p:
                payload = {"scenario": "burst", "mode": "inprocess"}
            elif "config" in p:
                payload = {"tcp_max_connections": 40}
            elif "block" in p and "unblock" not in p:
                payload = {"ttl_seconds": 60}
        if payload is not None:
            return {"json": payload}
        return {}
        
    async def call_as(role, expected_status, is_admin=False):
        # Fresh incident for each role test so we don't hit 409 State Transition Error
        inc_id = f"inc_{uuid.uuid4().hex[:12]}"
        incident = Incident(
            id=inc_id,
            state=IncidentState.DETECTED if "contain" not in path and "resolve" not in path else IncidentState.INVESTIGATING if "contain" in path else IncidentState.CONTAINED, # noqa: E501
            title="Test Incident",
            source="system",
            service=ServiceName.TCP,
            severity=Severity.HIGH,
            correlation_id="uuid",
            simulation=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            actions=[],
        )
        stack.state.incidents.add(incident)
        
        # for unblock, admin gets 404 if not blocked. If we want 200 we should block it, but matrix expects 404. # noqa: E501
        
        actual_path = path.replace("{incident_id}", inc_id)
        
        async with AsyncClient(base_url=stack.base_url) as client:
            r = await client.request(method, actual_path, headers=get_headers(role), **get_kwargs(method, actual_path)) # noqa: E501
            assert r.status_code == expected_status
            
    await call_as(None, anon_status)
    await call_as("viewer", viewer_status)
    await call_as("operator", operator_status)
    await call_as("admin", admin_status, is_admin=True)

@pytest.mark.asyncio
async def test_authz_matrix_missing_incident(stack):
    async with AsyncClient(base_url=stack.base_url) as client:
        r = await client.post("/incidents/missing/acknowledge", headers=get_headers("viewer"))
        assert r.status_code == 403
        r = await client.post("/incidents/missing/acknowledge", headers=get_headers("admin"))
        assert r.status_code == 404

def test_meta_matrix_rows(stack):
    assert len(MATRIX) >= 20
