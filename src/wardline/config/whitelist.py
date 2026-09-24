"""Whitelist of operational configuration parameters that can be inspected and patched."""

from typing import Any

from wardline.config.settings import Settings
from wardline.contracts import ErrorCode
from wardline.errors import WardlineError

# Only operational parameters: rate limits, quotas, timeouts, limits.
# Explicitly PROHIBITED: database_url, dev_api_keys, http_host, tcp_host, udp_host,
# http_port, tcp_port, udp_port, app_name, app_version, environment.
CONFIG_WHITELIST: frozenset[str] = frozenset(
    {
        "rate_limit_requests_per_minute",
        "rate_limit_burst",
        "quota_events_per_client",
        "block_ttl_seconds",
        "tcp_max_connections",
        "tcp_read_timeout_seconds",
        "tcp_idle_timeout_seconds",
        "tcp_max_message_bytes",
        "tcp_max_errors_per_session",
        "udp_max_datagram_bytes",
        "udp_packets_per_second",
        "http_max_body_bytes",
        "circuit_failure_threshold",
        "circuit_window_seconds",
        "circuit_open_seconds",
        "simulation_max_events",
        "simulation_loopback_max_connections",
        "simulation_loopback_max_datagrams",
        "simulation_loopback_max_seconds",
    }
)


def get_whitelisted_config(settings: Settings) -> dict[str, Any]:
    """Extract whitelisted operational values from settings."""
    return {key: getattr(settings, key) for key in sorted(CONFIG_WHITELIST)}


def validate_config_patch(
    patch: dict[str, Any], current_settings: Settings | None = None
) -> dict[str, Any]:
    """Validate that patch keys are all in the whitelist and values are valid.

    Raises WardlineError(validation_error) for any unknown key, non-whitelisted key,
    or out-of-range value.
    """
    if not isinstance(patch, dict) or not patch:
        raise WardlineError(ErrorCode.validation_error, "patch must be a non-empty object")

    for key in patch:
        if key not in CONFIG_WHITELIST:
            raise WardlineError(
                ErrorCode.validation_error,
                f"configuration key '{key}' is not allowed in whitelist",
            )

    from wardline.config.settings import validate_settings

    base = current_settings or Settings()
    try:
        updated = base.model_copy(update=patch)
        validate_settings(updated)
    except WardlineError:
        raise
    except Exception as exc:
        raise WardlineError(ErrorCode.validation_error, f"invalid patch: {exc}") from exc

    return patch
