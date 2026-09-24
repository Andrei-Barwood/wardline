"""Integration test for Chapter 2: Role boundaries on live stack."""

import httpx
import pytest

from tests.integration.conftest import Stack


@pytest.mark.asyncio
async def test_chapter2_roles_on_live_stack(stack: Stack) -> None:
    async with httpx.AsyncClient(base_url=stack.base_url, timeout=2.0) as client:
        # 1. Anónimo GET /metrics 401
        resp = await client.get("/metrics")
        assert resp.status_code == 401

        # 2. Viewer GET /metrics 200
        headers_viewer = {"Authorization": "Bearer dev-viewer-key"}
        resp = await client.get("/metrics", headers=headers_viewer)
        assert resp.status_code == 200

        # 3. Viewer POST /simulation/run 403
        resp = await client.post(
            "/simulation/run",
            headers=headers_viewer,
            json={"scenario": "burst", "mode": "inprocess"},
        )
        assert resp.status_code == 403

        # 4. Operator POST /simulation/run scenario burst mode inprocess 200
        headers_operator = {"Authorization": "Bearer dev-operator-key"}
        resp = await client.post(
            "/simulation/run",
            headers=headers_operator,
            json={"scenario": "burst", "mode": "inprocess"},
        )
        assert resp.status_code == 200
        assert resp.json().get("scenario") == "burst"

        # 5. Admin GET /admin/config 200
        headers_admin = {"Authorization": "Bearer dev-admin-key"}
        resp = await client.get("/admin/config", headers=headers_admin)
        assert resp.status_code == 200

        # 6. Operator POST /admin/config 403
        resp = await client.post(
            "/admin/config",
            headers=headers_operator,
            json={"rate_limit_burst": 5},
        )
        assert resp.status_code == 403
