"""Unit tests for JSON logging and configuration."""

import io
import json

from wardline.config.settings import Settings
from wardline.logsetup import configure_logging, get_logger


def test_json_log_line_has_required_fields() -> None:
    stream = io.StringIO()
    settings = Settings(log_format="json", dev_api_keys="admin:dev-admin-key")
    configure_logging(settings, stream=stream, replace=True)

    logger = get_logger("wardline.api")
    logger.info("server initialized", extra={"service": "http", "correlation_id": "corr-12345"})

    output = stream.getvalue().strip()
    assert output
    record = json.loads(output)

    assert "timestamp" in record
    assert record["level"] == "INFO"
    assert record["logger"] == "wardline.api"
    assert record["message"] == "server initialized"
    assert record["service"] == "http"
    assert record["correlation_id"] == "corr-12345"
    assert record["simulation"] is False


def test_configure_logging_is_idempotent() -> None:
    stream = io.StringIO()
    settings = Settings(log_format="json")

    # Calling configure_logging multiple times does not duplicate handlers or log lines
    configure_logging(settings, stream=stream, replace=True)
    configure_logging(settings, stream=stream, replace=False)
    configure_logging(settings, stream=stream, replace=False)

    logger = get_logger("wardline.test")
    logger.info("single message")

    lines = [line for line in stream.getvalue().splitlines() if line.strip()]
    assert len(lines) == 1
