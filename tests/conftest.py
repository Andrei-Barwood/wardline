"""Pytest fixtures for Wardline. This module does not start servers."""

from collections.abc import AsyncIterator, Callable
from pathlib import Path

import httpx
import pytest

from wardline.api.app import create_app
from wardline.config.settings import Settings
from wardline.contracts import Role
from wardline.runtime import build_state

_FAKE_KEYS = {
    Role.VIEWER: "dev-viewer-key",
    Role.OPERATOR: "dev-operator-key",
    Role.ADMIN: "dev-admin-key",
}


@pytest.fixture
def settings_factory(tmp_path: Path) -> Callable[..., Settings]:
    """Build valid Settings for tests. Ports default to ephemeral (0)."""

    def factory(**overrides: object) -> Settings:
        values: dict[str, object] = {
            "http_port": 0,
            "tcp_port": 0,
            "udp_port": 0,
            "database_url": f"sqlite:///{tmp_path / 'wardline.db'}",
            "dev_api_keys": ("viewer:dev-viewer-key,operator:dev-operator-key,admin:dev-admin-key"),
            "rate_limit_requests_per_minute": 60,
            "rate_limit_burst": 2,
        }
        values.update(overrides)
        return Settings(**values)

    return factory


@pytest.fixture
def auth_header() -> Callable[[Role | str], dict[str, str]]:
    """Return a Bearer header for one of the fictional laboratory roles."""

    def header(role: Role | str) -> dict[str, str]:
        selected = Role(role)
        return {"Authorization": f"Bearer {_FAKE_KEYS[selected]}"}

    return header


@pytest.fixture
def tcp_hello() -> Callable[..., dict[str, object]]:
    """Return a hello payload with the fictional laboratory token for the given role."""

    def factory(
        client_id: str = "training-client", role: Role | str = Role.VIEWER
    ) -> dict[str, object]:
        selected = Role(role)
        return {
            "type": "hello",
            "client_id": client_id,
            "token": _FAKE_KEYS[selected],
        }

    return factory


@pytest.fixture
async def api_client(
    settings_factory: Callable[..., Settings],
) -> AsyncIterator[httpx.AsyncClient]:
    """HTTP client bound to the ASGI app. It does not open a socket."""
    state = build_state(settings_factory())
    app = create_app(state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        yield client
