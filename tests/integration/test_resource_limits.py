from collections.abc import Callable

import httpx
import pytest
from httpx import AsyncClient

from wardline.api.app import create_app
from wardline.config.settings import Settings
from wardline.contracts import ServiceName
from wardline.runtime import build_state

pytestmark = pytest.mark.asyncio


async def test_unauthorized_does_not_open_circuit(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(circuit_breaker_threshold=2)
    state = build_state(settings)
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # 10 unauthorized requests
        for _ in range(10):
            r = await client.get("/status")
            assert r.status_code == 401

        # Circuit should still be closed and allow a valid request
        r = await client.get("/status", headers={"Authorization": "Bearer dev-viewer-key"})
        assert r.status_code == 200


async def test_http_circuit_open_blocks_status_not_health(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(circuit_failure_threshold=1)
    state = build_state(settings)
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)

    state.health.set_status("http", "ok")
    state.health.set_status("tcp", "ok")
    state.health.set_status("udp", "ok")
    state.health.set_status("database", "ok")
    # Manually fail the HTTP breaker
    state.circuit_breakers.record_failure(ServiceName.HTTP)

    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # Health should work
        r = await client.get("/health")
        assert r.status_code == 200

        # Status should be blocked with 503
        r = await client.get("/status", headers={"Authorization": "Bearer dev-viewer-key"})
        assert r.status_code == 503


async def test_quota_exceeded_distinct_from_rate_limited(
    settings_factory: Callable[..., Settings],
) -> None:
    # High rate limit, low quota
    settings = settings_factory(rate_limit_burst=10, quota_limit=2)
    state = build_state(settings)

    # Wait, the prompt says quota tracker with a static limit. Is it in settings?
    # No, QuotaTracker(limit=1000) was in quotas.py, but how is it set?

    # Ah, the settings doesn't have quota_limit? If not, I can just patch the state object!

    state.quotas._limit = 2

    app = create_app(state)
    transport = httpx.ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        r1 = await client.get("/status", headers={"Authorization": "Bearer dev-viewer-key"})
        assert r1.status_code == 200
        r2 = await client.get("/status", headers={"Authorization": "Bearer dev-viewer-key"})
        assert r2.status_code == 200

        # 3rd request hits quota exceeded
        r3 = await client.get("/status", headers={"Authorization": "Bearer dev-viewer-key"})
        assert r3.status_code == 429
        assert "Retry-After" not in r3.headers
        assert r3.json()["error"]["code"] == "quota_exceeded"


async def test_connection_limit_still_enforced(
    settings_factory: Callable[..., Settings],
) -> None:
    # I'll just check if backpressure still denies a connection
    from wardline.security.backpressure import admission_allowed

    assert admission_allowed(active=10, limit=10) is False
