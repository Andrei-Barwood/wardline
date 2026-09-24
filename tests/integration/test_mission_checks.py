from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from wardline.api.app import create_app
from wardline.auth.api_keys import parse_dev_api_keys
from wardline.contracts import Role
from wardline.logsetup import configure_logging, get_logger
from wardline.missions.checks import (
    check_m01,
    check_m02,
    check_m03,
    check_m04,
    check_m05,
)
from wardline.runtime import build_state
from wardline.serve import start_http, start_tcp, start_udp


@pytest.mark.integration
async def test_m01_passes_when_stack_is_up(settings_factory) -> None:
    settings = settings_factory(http_port=0, tcp_port=0, udp_port=0, rate_limit_burst=20)
    configure_logging(settings)
    state = build_state(settings)

    http_server = await start_http(state)
    tcp_server = await start_tcp(state)
    udp_server = await start_udp(state)

    logger = get_logger("wardline.mission")
    logger.info("service stack is running")

    keys = parse_dev_api_keys(state.settings.dev_api_keys)
    operator_key = keys[Role.OPERATOR]
    headers = {"Authorization": f"Bearer {operator_key}"}

    try:
        transport = ASGITransport(app=create_app(state))
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/missions/m01/check", headers=headers)
            assert resp.status_code == 200
            body = resp.json()
            assert body["mission_id"] == "m01"
            assert body["passed"] is True
            assert "explanation" in body
    finally:
        await udp_server.stop()
        await tcp_server.stop()
        await http_server.stop()


@pytest.mark.integration
async def test_m01_fails_when_udp_down(settings_factory) -> None:
    state = build_state(settings_factory())
    state.health.set_status("udp", "down")

    res = await check_m01(state)
    assert res.passed is False
    assert any("udp" in obs for obs in res.observations)


@pytest.mark.integration
async def test_m02_passes_on_auth_boundaries(settings_factory) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    res = await check_m02(state)
    assert res.passed is True
    assert any("401" in obs for obs in res.observations)
    assert any("403" in obs for obs in res.observations)


@pytest.mark.integration
async def test_m03_passes_after_burst(settings_factory) -> None:
    state = build_state(settings_factory())
    res = await check_m03(state)
    assert res.passed is True
    assert any("simulated_rate_abuse" in obs for obs in res.observations)


@pytest.mark.integration
async def test_m04_passes_after_pressure_event(settings_factory) -> None:
    state = build_state(settings_factory())
    res = await check_m04(state)
    assert res.passed is True
    assert any("simulated_connection_pressure" in obs for obs in res.observations)


@pytest.mark.integration
async def test_m05_passes_full_cycle(settings_factory) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    # Mark local health as ok
    state.health.set_status("http", "ok")
    state.health.set_status("tcp", "ok")
    state.health.set_status("udp", "ok")
    state.health.set_status("database", "ok")

    res = await check_m05(state)
    assert res.passed is True
    assert any("RESOLVED" in obs for obs in res.observations)


@pytest.mark.integration
async def test_check_exception_returns_failed_result_not_500(settings_factory) -> None:
    state = build_state(settings_factory(rate_limit_burst=20))
    keys = parse_dev_api_keys(state.settings.dev_api_keys)
    operator_key = keys[Role.OPERATOR]
    headers = {"Authorization": f"Bearer {operator_key}"}

    async def _failing_check(_: object) -> None:
        raise RuntimeError("database exploded")

    transport = ASGITransport(app=create_app(state))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("wardline.missions.runner._CHECKS", {"m01": _failing_check}):
            resp = await client.post("/missions/m01/check", headers=headers)
            # Must return 200 (not 500), student sees failed check
            assert resp.status_code == 200
            body = resp.json()
            assert body["mission_id"] == "m01"
            assert body["passed"] is False
            assert "check failed" in body["observations"]
            assert "database exploded" not in str(body)
