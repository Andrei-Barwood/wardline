"""Laboratory settings loaded from defaults, config/default.toml, and the environment."""

from pathlib import Path

from pydantic import model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

from wardline import __version__
from wardline.contracts import ErrorCode, Severity
from wardline.errors import WardlineError

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
LOG_FORMATS = frozenset({"json", "text"})
SIMULATION_MODES = frozenset({"inprocess", "loopback"})


def default_toml_path() -> Path:
    """Locate config/default.toml from the source tree, then from the working directory."""
    packaged = Path(__file__).resolve().parents[3] / "config" / "default.toml"
    if packaged.is_file():
        return packaged
    return Path.cwd() / "config" / "default.toml"


class Settings(BaseSettings):
    """Defaults for a laboratory that listens only on loopback.

    Port 0 is accepted so tests can ask the operating system for an ephemeral port.
    Every other port must sit in 1024..65535.
    """

    model_config = SettingsConfigDict(
        env_prefix="WARDLINE_",
        env_file=".env",
        extra="ignore",
    )

    container: int = 0
    app_name: str = "wardline"
    app_version: str = __version__
    environment: str = "local"
    log_level: str = "INFO"
    log_format: str = "json"
    http_host: str = "127.0.0.1"
    http_port: int = 8080
    tcp_host: str = "127.0.0.1"
    tcp_port: int = 9001
    udp_host: str = "127.0.0.1"
    udp_port: int = 9002
    tcp_max_connections: int = 32
    tcp_read_timeout_seconds: float = 5.0
    tcp_idle_timeout_seconds: float = 30.0
    tcp_max_message_bytes: int = 4096
    tcp_max_errors_per_session: int = 5
    udp_max_datagram_bytes: int = 1024
    udp_packets_per_second: int = 20
    http_max_body_bytes: int = 65536
    database_url: str = "sqlite:///./data/wardline.db"
    dev_api_keys: str = ""
    rate_limit_requests_per_minute: int = 60
    rate_limit_burst: int = 10
    quota_events_per_client: int = 1000
    circuit_failure_threshold: int = 5
    circuit_window_seconds: float = 10.0
    circuit_open_seconds: float = 15.0
    block_ttl_seconds: int = 300
    anomaly_incident_min_severity: str = "HIGH"
    simulation_mode_default: str = "inprocess"
    simulation_max_events: int = 50
    simulation_loopback_max_connections: int = 8
    simulation_loopback_max_datagrams: int = 20
    simulation_loopback_max_seconds: float = 2.0

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        sources: tuple[PydanticBaseSettingsSource, ...] = (
            init_settings,
            env_settings,
            dotenv_settings,
        )
        path = default_toml_path()
        if path.is_file():
            sources = (
                *sources,
                TomlConfigSettingsSource(settings_cls, toml_file=path),
            )
        return (*sources, file_secret_settings)

    @model_validator(mode="after")
    def _enforce_laboratory_limits(self) -> "Settings":
        validate_settings(self)
        return self


def _require_range(name: str, value: float, low: float, high: float) -> None:
    if value < low or value > high:
        raise WardlineError(ErrorCode.validation_error, f"{name} is outside the allowed range")


def _valid_port(port: object) -> bool:
    if isinstance(port, bool) or not isinstance(port, int):
        return False
    return port == 0 or 1024 <= port <= 65535


def validate_settings(settings: Settings) -> None:
    """Reject settings that would leave the local laboratory.

    Raises WardlineError(validation_error) for a non-loopback host, a port other
    than 0 or 1024..65535, or a database URL that does not start with sqlite.
    This function does not open a socket or a database file.
    """
    container_flag = getattr(settings, "container", 0) == 1
    for name in ("http_host", "tcp_host", "udp_host"):
        host = getattr(settings, name)
        if host == "container":
            if container_flag:
                setattr(settings, name, "0.0.0.0")
            else:
                raise WardlineError(ErrorCode.validation_error, f"{name} 'container' requires WARDLINE_CONTAINER=1") # noqa: E501
        elif host not in LOOPBACK_HOSTS:
            raise WardlineError(ErrorCode.validation_error, f"{name} must be a loopback address")
    for name in ("http_port", "tcp_port", "udp_port"):
        if not _valid_port(getattr(settings, name)):
            raise WardlineError(
                ErrorCode.validation_error,
                f"{name} must be 0 or between 1024 and 65535",
            )
    if not str(settings.database_url).startswith("sqlite"):
        raise WardlineError(ErrorCode.validation_error, "database_url must use sqlite")
    if settings.log_level not in LOG_LEVELS:
        raise WardlineError(ErrorCode.validation_error, "log_level is not supported")
    if settings.log_format not in LOG_FORMATS:
        raise WardlineError(ErrorCode.validation_error, "log_format is not supported")
    if settings.simulation_mode_default not in SIMULATION_MODES:
        raise WardlineError(ErrorCode.validation_error, "simulation_mode_default is not supported")
    allowed_severity = {item.value for item in Severity}
    if settings.anomaly_incident_min_severity not in allowed_severity:
        raise WardlineError(
            ErrorCode.validation_error,
            "anomaly_incident_min_severity is not supported",
        )
    _require_range("tcp_max_connections", settings.tcp_max_connections, 1, 64)
    _require_range("tcp_read_timeout_seconds", settings.tcp_read_timeout_seconds, 0.1, 30)
    _require_range("tcp_idle_timeout_seconds", settings.tcp_idle_timeout_seconds, 1, 120)
    _require_range("tcp_max_message_bytes", settings.tcp_max_message_bytes, 128, 8192)
    _require_range("udp_max_datagram_bytes", settings.udp_max_datagram_bytes, 64, 2048)
    _require_range("udp_packets_per_second", settings.udp_packets_per_second, 1, 100)
    _require_range(
        "rate_limit_requests_per_minute",
        settings.rate_limit_requests_per_minute,
        1,
        600,
    )
    _require_range("rate_limit_burst", settings.rate_limit_burst, 1, 60)
    _require_range("quota_events_per_client", settings.quota_events_per_client, 10, 10000)
    _require_range("block_ttl_seconds", settings.block_ttl_seconds, 1, 3600)
    _require_range("simulation_max_events", settings.simulation_max_events, 1, 100)


def load_settings() -> Settings:
    """Load toml defaults, then let the environment and an optional .env file win."""
    return Settings()
