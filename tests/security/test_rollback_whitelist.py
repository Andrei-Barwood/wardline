import pytest
from httpx import ASGITransport, AsyncClient

from wardline.api.app import create_app
from wardline.auth.api_keys import parse_dev_api_keys
from wardline.config.whitelist import CONFIG_WHITELIST
from wardline.contracts import Role
from wardline.runtime import build_state


@pytest.mark.security
async def test_get_config_hides_sensitive_keys(settings_factory) -> None:
    state = build_state(settings_factory())
    keys = parse_dev_api_keys(state.settings.dev_api_keys)
    admin_key = keys[Role.ADMIN]

    transport = ASGITransport(app=create_app(state))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/admin/config",
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert resp.status_code == 200
        values = resp.json()["values"]
        assert "dev_api_keys" not in values
        assert "database_url" not in values
        assert "http_host" not in values
        assert "tcp_host" not in values
        assert "udp_host" not in values
        for key in values:
            assert key in CONFIG_WHITELIST


@pytest.mark.security
@pytest.mark.parametrize(
    "forbidden_patch",
    [
        {"dev_api_keys": "admin:evil_token"},
        {"database_url": "sqlite:////tmp/pwned.db"},
        {"http_host": "0.0.0.0"},
        {"tcp_host": "8.8.8.8"},
        {"udp_host": "1.1.1.1"},
        {"http_port": 80},
        {"tcp_port": 22},
        {"malicious_key": "some_value"},
    ],
)
async def test_post_config_rejects_forbidden_keys(settings_factory, forbidden_patch) -> None:
    state = build_state(settings_factory())
    keys = parse_dev_api_keys(state.settings.dev_api_keys)
    admin_key = keys[Role.ADMIN]

    transport = ASGITransport(app=create_app(state))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/admin/config",
            headers={"Authorization": f"Bearer {admin_key}"},
            json=forbidden_patch,
        )
        assert resp.status_code == 400
        error = resp.json()["error"]
        assert error["code"] == "validation_error"

        # Check generation did not increment
        assert state.config_history.current_generation() == 0
