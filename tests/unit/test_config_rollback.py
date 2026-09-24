import inspect
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from wardline.api.app import create_app
from wardline.auth.api_keys import parse_dev_api_keys
from wardline.config.whitelist import CONFIG_WHITELIST, validate_config_patch
from wardline.contracts import Role
from wardline.errors import ErrorCode, WardlineError
from wardline.incidents.recovery import LocalHealthGate
from wardline.runtime import build_state
from wardline.storage.cleanup import safe_reset


def test_whitelist_rejects_host_and_database_url() -> None:
    # Whitelist must not contain sensitive parameters
    assert "http_host" not in CONFIG_WHITELIST
    assert "tcp_host" not in CONFIG_WHITELIST
    assert "udp_host" not in CONFIG_WHITELIST
    assert "database_url" not in CONFIG_WHITELIST
    assert "dev_api_keys" not in CONFIG_WHITELIST
    assert "http_port" not in CONFIG_WHITELIST

    # Validation rejects host and database_url
    with pytest.raises(WardlineError) as exc_info:
        validate_config_patch({"http_host": "127.0.0.1"})
    assert exc_info.value.code == ErrorCode.validation_error

    with pytest.raises(WardlineError) as exc_info:
        validate_config_patch({"database_url": "sqlite:///other.db"})
    assert exc_info.value.code == ErrorCode.validation_error


def test_whitelist_rejects_out_of_range_burst() -> None:
    # rate_limit_burst must be between 1 and 60
    with pytest.raises(WardlineError) as exc_info:
        validate_config_patch({"rate_limit_burst": 0})
    assert exc_info.value.code == ErrorCode.validation_error

    with pytest.raises(WardlineError) as exc_info:
        validate_config_patch({"rate_limit_burst": 1001})
    assert exc_info.value.code == ErrorCode.validation_error

    # Valid value passes
    patch = validate_config_patch({"rate_limit_burst": 5})
    assert patch["rate_limit_burst"] == 5


async def test_patch_then_limiter_sees_new_burst(settings_factory) -> None:
    state = build_state(settings_factory(rate_limit_burst=10))
    keys = parse_dev_api_keys(state.settings.dev_api_keys)
    admin_key = keys[Role.ADMIN]

    transport = ASGITransport(app=create_app(state))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Patch burst to 1
        resp = await client.post(
            "/admin/config",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={"rate_limit_burst": 1},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["applied"]["rate_limit_burst"] == 1
        assert state.settings.rate_limit_burst == 1

        # Rate limiter uses state.settings via callable, so it immediately sees burst=1
        # Consuming 1 token succeeds
        assert state.rate_limiter.allow("user-test-limiter", cost=1) is True
        # Consuming a second token without time passage fails
        assert state.rate_limiter.allow("user-test-limiter", cost=1) is False


async def test_rollback_restores_burst(settings_factory) -> None:
    state = build_state(settings_factory(rate_limit_burst=10))
    keys = parse_dev_api_keys(state.settings.dev_api_keys)
    admin_key = keys[Role.ADMIN]

    transport = ASGITransport(app=create_app(state))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        initial_burst = state.settings.rate_limit_burst

        # Patch burst to 5
        resp_patch = await client.post(
            "/admin/config",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={"rate_limit_burst": 5},
        )
        assert resp_patch.status_code == 200
        assert state.settings.rate_limit_burst == 5

        # Rollback
        resp_rb = await client.post(
            "/admin/recovery/rollback",
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert resp_rb.status_code == 200
        body = resp_rb.json()
        assert "restored" in body
        assert state.settings.rate_limit_burst == initial_burst


async def test_rollback_without_patch_409(settings_factory) -> None:
    state = build_state(settings_factory())
    keys = parse_dev_api_keys(state.settings.dev_api_keys)
    admin_key = keys[Role.ADMIN]

    transport = ASGITransport(app=create_app(state))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Initial rollback before any patch returns 409
        resp = await client.post(
            "/admin/recovery/rollback",
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert resp.status_code == 409
        assert resp.json()["error"]["code"] == "invalid_state_transition"


def test_health_probe_does_not_accept_custom_host() -> None:
    # LocalHealthGate must not have a public host parameter
    sig_init = inspect.signature(LocalHealthGate.__init__)
    assert "host" not in sig_init.parameters

    sig_check = inspect.signature(LocalHealthGate.check)
    assert "host" not in sig_check.parameters

    sig_report = inspect.signature(LocalHealthGate.report)
    assert "host" not in sig_report.parameters


def test_reset_script_removes_only_data_files(tmp_path: Path) -> None:
    # safe_reset rejects any directory whose name is not 'data'
    not_data = tmp_path / "somedir"
    not_data.mkdir()
    with pytest.raises(ValueError, match="Refusing to reset directory not named 'data'"):
        safe_reset(not_data)

    # Valid data directory
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    # Create allowed files
    db_file = data_dir / "wardline.db"
    db_file.write_text("db")
    wal_file = data_dir / "wardline.db-wal"
    wal_file.write_text("wal")
    jsonl_file = data_dir / "events.jsonl"
    jsonl_file.write_text("{}")

    # Create protected files that must not be deleted
    code_file = data_dir / "source.py"
    code_file.write_text("print('hello')")
    env_file = data_dir / ".env"
    env_file.write_text("KEY=val")

    removed = safe_reset(data_dir)
    removed_names = {p.name for p in removed}
    assert removed_names == {"wardline.db", "wardline.db-wal", "events.jsonl"}

    # Verify disk state
    assert not db_file.exists()
    assert not wal_file.exists()
    assert not jsonl_file.exists()
    assert code_file.exists()
    assert env_file.exists()
