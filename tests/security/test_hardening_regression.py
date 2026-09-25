import pytest
from pathlib import Path
import re
from httpx import AsyncClient

from wardline.config.settings import Settings, validate_settings
from wardline.errors import WardlineError
from wardline.api.app import create_app

@pytest.mark.asyncio
async def test_hardening_validate_settings():
    with pytest.raises(WardlineError) as exc_info:
        s = Settings(http_host="0.0.0.0")
        validate_settings(s)
    assert "loopback address" in str(exc_info.value)
    
    with pytest.raises(WardlineError) as exc_info:
        s = Settings(tcp_host="8.8.8.8")
        validate_settings(s)
    assert "loopback address" in str(exc_info.value)

def test_hardening_create_app():
    app = create_app()
    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None

def test_hardening_public_router():
    app = create_app()
    assert not any(getattr(r, "path", None) == "/debug" for r in app.routes)
    assert not any(getattr(r, "path", None) == "/shutdown" for r in app.routes)
    assert not any(getattr(r, "path", None) == "/eval" for r in app.routes)

def test_hardening_no_forbidden_strings():
    src_dir = Path("src")
    forbidden = [
        r"subprocess\.", r"shell=True", r"eval\(", r"exec\(",
        r"pickle\.loads", r"verify=False", r"iptables", r"pfctl", r"scapy", r"nmap",
        r"os\.system", r"dev-viewer-key", r"dev-operator-key", r"dev-admin-key"
    ]
    
    py_files = list(src_dir.rglob("*.py"))
    for file in py_files:
        content = file.read_text(encoding="utf-8")
        for f in forbidden:
            assert not re.search(f, content), f"Forbidden string {f} found in {file}"

@pytest.mark.asyncio
async def test_hardening_health_no_env_keys(stack):
    async with AsyncClient(base_url=stack.base_url) as client:
        r = await client.get("/health")
        assert r.status_code == 200
        text = r.text
        assert "dev-viewer-key" not in text
        assert "dev-operator-key" not in text
        assert "dev-admin-key" not in text

def test_hardening_block_registry_no_block_ip():
    from wardline.clients.blocks import BlockRegistry, InMemoryBlockRegistry
    assert not hasattr(BlockRegistry, "block_ip")
    assert not hasattr(InMemoryBlockRegistry, "block_ip")

def test_hardening_docker_compose():
    path = Path("docker-compose.yml")
    if not path.exists():
        return
    content = path.read_text()
    assert "127.0.0.1:8080:8080" in content
    assert "cap_drop:" in content
    assert "- ALL" in content

def test_hardening_ci_workflow():
    path = Path(".github/workflows/tests.yml")
    if not path.exists():
        return
    content = path.read_text()
    assert "pull_request_target" not in content

def test_hardening_no_cors_or_static():
    src_dir = Path("src")
    py_files = list(src_dir.rglob("*.py"))
    for file in py_files:
        content = file.read_text(encoding="utf-8")
        assert "allow_origins" not in content, f"CORS allow_origins found in {file}"
        assert "StaticFiles" not in content, f"StaticFiles found in {file}"
        assert "mount" not in content and "mount(" not in content, f"mount() found in {file}"

def test_hardening_error_500_no_traceback():
    from wardline.api.app import _install_handlers
    from wardline.errors import ErrorCode
    import json
    import asyncio
    
    app = create_app()
    handler = app.exception_handlers.get(Exception)
    
    class MockState:
        correlation_id = "test-id"

    class MockRequest:
        scope = {"headers": []}
        state = MockState()
    
    response = asyncio.run(handler(MockRequest(), ValueError("Secret traceback data")))
    assert response.status_code == 500
    body = json.loads(response.body.decode())
    assert "internal error" in body["error"]["message"]
    assert "Secret traceback data" not in body["error"]["message"]
    assert "Traceback" not in response.body.decode()

@pytest.mark.asyncio
async def test_hardening_inprocess_simulator_no_sockets(monkeypatch):
    import socket
    from wardline.simulation.engine import simulate_all
    from wardline.runtime import build_state
    from wardline.config.settings import load_settings
    
    called_sockets = []
    
    def fake_create_connection(*args, **kwargs):
        called_sockets.append(args)
        raise ConnectionRefusedError("Simulated refusal")
        
    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    
    state = build_state(load_settings())
    # Should not invoke socket.create_connection since it's inprocess
    res = await simulate_all(state, mode="inprocess")
    assert res.events_recorded > 0
    assert len(called_sockets) == 0
