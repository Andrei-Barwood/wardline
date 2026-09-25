"""Settings loading, validation, and fictional API-key parsing."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from wardline.auth.api_keys import parse_dev_api_keys
from wardline.config.settings import Settings, load_settings
from wardline.contracts import ErrorCode, Role
from wardline.errors import WardlineError

_ROOT = Path(__file__).resolve().parents[2]
_FAKE_RAW = "viewer:dev-viewer-key,operator:dev-operator-key,admin:dev-admin-key"


def test_defaults_are_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("WARDLINE_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(_ROOT)
    settings = Settings(_env_file=None)
    assert settings.http_host == "127.0.0.1"
    assert settings.tcp_host == "127.0.0.1"
    assert settings.udp_host == "127.0.0.1"
    assert settings.http_port == 8080
    assert settings.tcp_port == 9001
    assert settings.udp_port == 9002


def test_env_overrides_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDLINE_HTTP_PORT", "8123")
    settings = load_settings()
    assert settings.http_port == 8123


def test_rejects_wildcard_host() -> None:
    with pytest.raises(WardlineError) as caught:
        Settings(http_host="0.0.0.0")
    assert caught.value.code == ErrorCode.validation_error


def test_rejects_public_ip() -> None:
    with pytest.raises(WardlineError) as caught:
        Settings(tcp_host="203.0.113.10")
    assert caught.value.code == ErrorCode.validation_error


def test_rejects_low_port() -> None:
    with pytest.raises(WardlineError) as caught:
        Settings(http_port=80)
    assert caught.value.code == ErrorCode.validation_error


def test_rejects_non_sqlite() -> None:
    with pytest.raises(WardlineError) as caught:
        Settings(database_url="postgres://localhost/wardline")
    assert caught.value.code == ErrorCode.validation_error


def test_limits_out_of_range_rejected() -> None:
    with pytest.raises(WardlineError):
        Settings(tcp_max_connections=65)
    with pytest.raises(WardlineError):
        Settings(rate_limit_burst=0)
    with pytest.raises(WardlineError):
        Settings(simulation_max_events=101)


def test_parse_dev_api_keys_roundtrip() -> None:
    parsed = parse_dev_api_keys(_FAKE_RAW)
    assert parsed == {
        Role.VIEWER: "dev-viewer-key",
        Role.OPERATOR: "dev-operator-key",
        Role.ADMIN: "dev-admin-key",
    }
    assert parse_dev_api_keys("") == {}
    assert parse_dev_api_keys("   ") == {}


def test_parse_dev_api_keys_rejects_unknown_role() -> None:
    with pytest.raises(WardlineError) as caught:
        parse_dev_api_keys("root:dev-viewer-key")
    assert caught.value.code == ErrorCode.validation_error
    with pytest.raises(WardlineError):
        parse_dev_api_keys("viewer:dev viewer")
    with pytest.raises(WardlineError):
        parse_dev_api_keys("viewer:dev-viewer-key,viewer:other-key")


def test_missing_env_file_is_ok(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from wardline.config.settings import load_settings; "
                "settings = load_settings(); "
                "assert settings.http_host == '127.0.0.1'; "
                "assert settings.tcp_host == '127.0.0.1'; "
                "assert settings.udp_host == '127.0.0.1'"
            ),
        ],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(_ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_env_example_has_only_fake_keys() -> None:
    text = (_ROOT / ".env.example").read_text(encoding="utf-8")
    for forbidden in ("sk-", "AKIA", "gh_", "xoxb-", "BEGIN PRIVATE KEY"):
        assert forbidden not in text
    assert "dev-viewer-key" in text
    assert "dev-operator-key" in text
    assert "dev-admin-key" in text
    assert "203.0.113." not in text


def test_settings_container_host():
    import pytest

    from wardline.config.settings import Settings
    from wardline.errors import WardlineError
    
    # container=1 y host container => aceptado
    s = Settings(container=1, http_host="container", tcp_host="container", udp_host="container")
    assert s.http_host == "0.0.0.0"
    assert s.tcp_host == "0.0.0.0"
    assert s.udp_host == "0.0.0.0"
    
    # container=0 y host container => rechazado
    with pytest.raises(WardlineError) as exc_info:
        Settings(container=0, http_host="container")
    assert "requires WARDLINE_CONTAINER=1" in str(exc_info.value)
    
    # container=1 y host 203.0.113.10 => rechazado
    with pytest.raises(WardlineError) as exc_info:
        Settings(container=1, http_host="203.0.113.10")
    assert "must be a loopback address" in str(exc_info.value)
    
    # container ausente y host 0.0.0.0 => rechazado
    with pytest.raises(WardlineError) as exc_info:
        Settings(http_host="0.0.0.0")
    assert "must be a loopback address" in str(exc_info.value)
