"""HTTP health, version, and status over the in-process ASGI app."""

from collections.abc import Callable

import httpx

from wardline import __version__
from wardline.api.app import create_app
from wardline.config.settings import Settings
from wardline.contracts import Role
from wardline.runtime import build_state


async def test_health_degraded_when_tcp_down(api_client: httpx.AsyncClient) -> None:
    """TCP is still down when only the HTTP app is built, so health stays degraded."""
    response = await api_client.get("/health")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["http"] == "ok"
    assert body["checks"]["database"] == "ok"
    assert body["checks"]["tcp"] == "down"
    assert body["checks"]["udp"] == "down"


async def test_version_matches_package(api_client: httpx.AsyncClient) -> None:
    response = await api_client.get("/version")
    assert response.status_code == 200
    assert response.json() == {"name": "wardline", "version": __version__}


async def test_status_shape_hides_secrets(
    api_client: httpx.AsyncClient,
    auth_header: Callable[[Role | str], dict[str, str]],
) -> None:
    response = await api_client.get("/status", headers=auth_header("viewer"))
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"app", "version", "environment", "started_at", "components", "bindings"}
    assert set(body["components"]) == {"http", "tcp", "udp", "database"}
    assert set(body["bindings"]) == {"http", "tcp", "udp"}
    text = response.text
    assert "dev-viewer-key" not in text
    assert "dev-operator-key" not in text
    assert "dev-admin-key" not in text


async def test_unknown_route_404_json(api_client: httpx.AsyncClient) -> None:
    response = await api_client.get("/missing")
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "not_found"
    assert "Traceback" not in response.text
    assert "<html" not in response.text.lower()


async def test_correlation_id_header_present(api_client: httpx.AsyncClient) -> None:
    response = await api_client.get("/version")
    correlation_id = response.headers.get("X-Correlation-ID")
    assert correlation_id is not None
    assert len(correlation_id) >= 32


async def test_oversized_body_rejected(api_client: httpx.AsyncClient) -> None:
    response = await api_client.request("GET", "/version", content=b"a" * 70_000)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "validation_error"
    assert response.headers.get("X-Correlation-ID")


async def test_error_body_has_no_traceback(
    settings_factory: Callable[..., Settings],
) -> None:
    class ExplodingHealth:
        def set_status(self, name: str, status: str) -> None:
            del name, status

        def snapshot(self) -> dict[str, str]:
            raise RuntimeError("boom /tmp/secret-trace")

    state = build_state(settings_factory())
    state.health = ExplodingHealth()  # type: ignore[assignment]
    app = create_app(state)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.get("/health")
    assert response.status_code == 500
    assert response.json()["error"] == {
        "code": "internal",
        "message": "internal error",
        "correlation_id": response.json()["error"]["correlation_id"],
    }
    assert "Traceback" not in response.text
    assert "secret-trace" not in response.text
    assert "/tmp/" not in response.text
