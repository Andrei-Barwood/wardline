"""JSON application logs. Records stay on the local process and never leave the machine."""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any, TextIO

from wardline.auth.api_keys import parse_dev_api_keys
from wardline.config.settings import Settings
from wardline.security.redaction import redact

_HANDLER_MARK = "_wardline_handler"
_EXTRA_FIELDS = ("client_id", "event_type", "status_code", "duration_ms", "method", "path")


class _RedactingFormatter(logging.Formatter):
    """Emit one log record as JSON, or as a single readable line."""

    def __init__(self, *, secrets: tuple[str, ...], as_json: bool) -> None:
        super().__init__()
        self._secrets = secrets
        self._as_json = as_json

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": getattr(record, "service", "system"),
            "correlation_id": getattr(record, "correlation_id", ""),
            "simulation": bool(getattr(record, "simulation", False)),
        }
        for field in _EXTRA_FIELDS:
            if hasattr(record, field):
                payload[field] = getattr(record, field)
        safe = redact(payload, secrets=self._secrets)
        if not self._as_json:
            return (
                f"{safe['timestamp']} {safe['level']} {safe['logger']} "
                f"service={safe['service']} correlation_id={safe['correlation_id']} "
                f"simulation={safe['simulation']} {safe['message']}"
            )
        return json.dumps(safe, ensure_ascii=False)


class _ServiceAdapter(logging.LoggerAdapter[logging.Logger]):
    """Attach service and correlation_id when the caller supplies them."""

    def process(self, msg: str, kwargs: Any) -> tuple[str, Any]:
        extra = dict(kwargs.get("extra") or {})
        extra.setdefault("service", self.extra.get("service", "system"))
        extra.setdefault("correlation_id", self.extra.get("correlation_id", ""))
        extra.setdefault("simulation", self.extra.get("simulation", False))
        kwargs["extra"] = extra
        return msg, kwargs


def get_logger(name: str) -> logging.LoggerAdapter[logging.Logger]:
    """Return a logger that accepts service and correlation_id in extra."""
    return _ServiceAdapter(logging.getLogger(name), {"service": "system", "correlation_id": ""})


def configure_logging(
    settings: Settings,
    *,
    stream: TextIO | None = None,
    replace: bool = True,
) -> None:
    """Attach one local handler to the wardline logger.

    Calling this twice does not stack handlers. replace=True removes only the
    handlers this function added earlier.
    """
    logger = logging.getLogger("wardline")
    if replace:
        logger.handlers = [handler for handler in logger.handlers if not getattr(handler, _HANDLER_MARK, False)]
    elif any(getattr(handler, _HANDLER_MARK, False) for handler in logger.handlers):
        return
    secrets = tuple(parse_dev_api_keys(settings.dev_api_keys).values())
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    setattr(handler, _HANDLER_MARK, True)
    handler.setFormatter(_RedactingFormatter(secrets=secrets, as_json=settings.log_format != "text"))
    logger.addHandler(handler)
    logger.setLevel(settings.log_level)
    logger.propagate = False
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    access = logging.getLogger("uvicorn.access")
    access.handlers.clear()
    access.propagate = False
    access.disabled = True
