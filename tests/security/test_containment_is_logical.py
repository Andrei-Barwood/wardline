import os
import subprocess
import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient

from wardline.contracts import IncidentState, ServiceName, Severity
from wardline.incidents.models import Incident


@pytest.mark.asyncio
async def test_containment_is_logical(stack, monkeypatch):
    inc_id = f"inc_{uuid.uuid4().hex[:12]}"
    incident = Incident(
        id=inc_id,
        state=IncidentState.DETECTED,
        title="Test Incident",
        source="attacker-client",
        service=ServiceName.TCP,
        severity=Severity.HIGH,
        correlation_id="uuid",
        simulation=False,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        actions=[],
    )
    stack.state.incidents.add(incident)
    
    def fake_popen(*args, **kwargs):
        pytest.fail("Subprocess called during containment!")
        
    def fake_system(*args, **kwargs):
        pytest.fail("os.system called during containment!")
        
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(os, "system", fake_system)
    
    async with AsyncClient(base_url=stack.base_url) as client:
        r = await client.post(f"/incidents/{inc_id}/acknowledge", headers={"Authorization": "Bearer dev-admin-key"}) # noqa: E501
        assert r.status_code == 200
        r = await client.post(f"/incidents/{inc_id}/contain", headers={"Authorization": "Bearer dev-admin-key"}) # noqa: E501
        assert r.status_code == 200
        
        assert stack.state.blocks.is_blocked("attacker-client", stack.state.clock.now())
        assert not stack.state.blocks.is_blocked("other_client", stack.state.clock.now())

def test_no_iptables_in_src():
    import os
    from pathlib import Path
    src_dir = Path("src")
    for root, _, files in os.walk(src_dir):
        for file in files:
            if file.endswith(".py"):
                content = (Path(root) / file).read_text(errors="ignore")
                assert "iptables" not in content
                assert "pfctl" not in content
