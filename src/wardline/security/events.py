import logging
from datetime import timedelta
from typing import Any

from wardline.contracts import SecurityEvent
from wardline.runtime import AppState


def redact(details: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of details with secrets redacted."""
    copy = dict(details)
    if "token" in copy:
        copy["token"] = "***"
    return copy


def record_event(state: AppState, event: SecurityEvent) -> None:
    # 1. Provide timestamp if missing or clamped
    event_dict = event.model_dump()
    details = dict(event_dict.get("details") or {})

    details = dict(event.details)

    now = state.clock.now()
    timestamp = event.timestamp
    clamped = False
    if timestamp > now + timedelta(minutes=5):
        timestamp = now
        clamped = True

    # 2. Redact details and source
    # Find all configured keys
    keys = []
    if state.settings.dev_api_keys:
        for entry in state.settings.dev_api_keys.split(","):
            if ":" in entry:
                keys.append(entry.split(":", 1)[1].strip())

    source = event.source
    for key in keys:
        if key:
            source = source.replace(key, "***")
            # Redact inside details
            for k, v in list(details.items()):
                if isinstance(v, str):
                    details[k] = v.replace(key, "***")

    if clamped:
        details["timestamp_clamped"] = True

    new_event = SecurityEvent(
        timestamp=timestamp,
        source=source,
        service=event.service,
        event_type=event.event_type,
        severity=event.severity,
        simulation=event.simulation,
        action=event.action,
        correlation_id=event.correlation_id,
        details=details,
    )

    # 3. Store in repository
    state.events.add(new_event)

    # 4. Store in audit log (swallow error)
    try:
        state.audit.append(new_event)
    except Exception:
        logging.getLogger("wardline.security").error("failed to append to audit log")

    # Later: trigger anomaly detection
