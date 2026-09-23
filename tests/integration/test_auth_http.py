"""HTTP authentication tests: header checking, status protection, and audit logging."""

from collections.abc import Callable

import httpx

from wardline.api.app import create_app
from wardline.audit.log import MemoryAuditLog
from wardline.config.settings import Settings
from wardline.contracts import ServiceName
from wardline.runtime import build_state


async def test_status_requires_key(api_client: httpx.AsyncClient) -> None:
    response = await api_client.get("/status")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert "Bearer" in response.headers["WWW-Authenticate"]

    valid_response = await api_client.get(
        "/status",
        headers={"Authorization": "Bearer dev-viewer-key"},
    )
    assert valid_response.status_code == 200
    assert valid_response.json()["app"] == "wardline"


async def test_health_stays_public_without_key(api_client: httpx.AsyncClient) -> None:
    health_resp = await api_client.get("/health")
    assert health_resp.status_code in (200, 503)

    version_resp = await api_client.get("/version")
    assert version_resp.status_code == 200


async def test_bearer_and_x_api_key_both_work(
    settings_factory: Callable[..., Settings],
) -> None:
    state = build_state(settings_factory())
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # Bearer header
        r1 = await client.get("/status", headers={"Authorization": "Bearer dev-viewer-key"})
        assert r1.status_code == 200

        # X-API-Key header
        r2 = await client.get("/status", headers={"X-API-Key": "dev-viewer-key"})
        assert r2.status_code == 200

        # Both headers matching
        r3 = await client.get(
            "/status",
            headers={"Authorization": "Bearer dev-viewer-key", "X-API-Key": "dev-viewer-key"},
        )
        assert r3.status_code == 200


async def test_mismatched_headers_rejected(
    settings_factory: Callable[..., Settings],
) -> None:
    state = build_state(settings_factory())
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.get(
            "/status",
            headers={"Authorization": "Bearer dev-viewer-key", "X-API-Key": "dev-operator-key"},
        )
        assert response.status_code == 401


async def test_auth_failure_is_audited_without_token_value(
    settings_factory: Callable[..., Settings],
) -> None:
    state = build_state(settings_factory())
    audit = MemoryAuditLog(clock=state.clock)
    state.audit = audit
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)

    bogus_token = "dev-admin-key-nope"
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.get(
            "/status",
            headers={"Authorization": f"Bearer {bogus_token}"},
        )
        assert response.status_code == 401

    auth_failures = [e for e in audit.events if e.event_type == "security_auth_failure"]
    assert len(auth_failures) >= 1
    event = auth_failures[0]
    assert event.service == ServiceName.AUTH
    assert event.action == "rejected"
    assert event.details == {"reason": "mismatch"}

    # Ensure the submitted token never appears in any audit record
    for ev in audit.events:
        dumped = ev.model_dump_json()
        assert bogus_token not in dumped
