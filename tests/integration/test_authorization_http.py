"""HTTP authorization tests: role restrictions, public vs protected routes, and audit."""

from collections.abc import Callable

import httpx
from fastapi import APIRouter, Depends
from starlette.routing import Route

from wardline.api.app import create_app
from wardline.api.deps import require_role
from wardline.audit.log import MemoryAuditLog
from wardline.config.settings import Settings
from wardline.contracts import Role, ServiceName
from wardline.runtime import build_state


def _app_with_admin_route(state: object) -> object:
    app = create_app(state)  # type: ignore[arg-type]
    test_router = APIRouter()

    @test_router.post("/_test/admin", dependencies=[Depends(require_role(Role.ADMIN))])
    def admin_endpoint() -> dict[str, str]:
        return {"status": "admin_granted"}

    app.include_router(test_router)
    return app


async def test_viewer_cannot_pass_admin_dependency(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory())
    app = _app_with_admin_route(state)
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.post("/_test/admin", headers=auth_header("viewer"))
        assert response.status_code == 403
        body = response.json()
        assert body["error"]["code"] == "forbidden"
        assert body["error"]["message"] == "forbidden"


async def test_operator_cannot_pass_admin_dependency(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory())
    app = _app_with_admin_route(state)
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.post("/_test/admin", headers=auth_header("operator"))
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "forbidden"


async def test_admin_can_pass_admin_dependency(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory())
    app = _app_with_admin_route(state)
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.post("/_test/admin", headers=auth_header("admin"))
        assert response.status_code == 200
        assert response.json() == {"status": "admin_granted"}


async def test_anonymous_is_401_not_403(
    settings_factory: Callable[..., Settings],
) -> None:
    state = build_state(settings_factory())
    app = _app_with_admin_route(state)
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.post("/_test/admin")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "unauthorized"


async def test_status_allowed_for_all_three_roles(
    api_client: httpx.AsyncClient,
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    for role in (Role.VIEWER, Role.OPERATOR, Role.ADMIN):
        response = await api_client.get("/status", headers=auth_header(role))
        assert response.status_code == 200
        assert "components" in response.json()


async def test_status_denied_without_credentials(api_client: httpx.AsyncClient) -> None:
    response = await api_client.get("/status")
    assert response.status_code == 401


async def test_forbidden_is_audited(
    settings_factory: Callable[..., Settings],
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    state = build_state(settings_factory())
    audit = MemoryAuditLog(clock=state.clock)
    state.audit = audit
    app = _app_with_admin_route(state)
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.post("/_test/admin", headers=auth_header("viewer"))
        assert response.status_code == 403

    denied = [e for e in audit.events if e.event_type == "security_authz_denied"]
    assert len(denied) >= 1
    event = denied[0]
    assert event.service == ServiceName.AUTH
    assert event.action == "denied"
    assert event.details == {"required": "admin"}
    assert state.metrics.to_dict()["http"]["forbidden_total"] >= 1


async def test_only_health_and_version_are_public(
    settings_factory: Callable[..., Settings],
) -> None:
    state = build_state(settings_factory())
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        for route in app.routes:
            if isinstance(route, Route):
                path = route.path
                if path in ("/health", "/version"):
                    resp = await client.request(list(route.methods or ["GET"])[0], path)
                    assert resp.status_code in (200, 503)
                else:
                    # All other routes must require credentials
                    resp = await client.request(list(route.methods or ["GET"])[0], path)
                    assert resp.status_code == 401, f"Route {path} should not be public"
