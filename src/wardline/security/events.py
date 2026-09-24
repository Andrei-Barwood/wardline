import logging
from datetime import timedelta
from typing import Any

from wardline.contracts import SEVERITY_RANK, SecurityEvent, Severity
from wardline.runtime import AppState


def redact(details: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of details with secrets redacted."""
    copy = dict(details)
    if "token" in copy:
        copy["token"] = "***"
    return copy


def record_event(state: AppState, event: SecurityEvent) -> None:
    # 1. Provide timestamp if missing or clamped
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
    state.metrics.bump("security", "events_total")
    
    # Is it an alert?
    if (
        new_event.event_type.startswith("anomaly_") or new_event.event_type.startswith("security_")
    ) and SEVERITY_RANK[new_event.severity] >= SEVERITY_RANK[Severity.LOW]:
        state.metrics.bump("security", "alerts_open")


    # 4. Store in audit log (swallow error)
    try:
        state.audit.append(new_event)
    except Exception:
        logging.getLogger("wardline.security").error("failed to append to audit log")

    # 5. Trigger anomaly detection
    # Do not observe recursively if this is an anomaly event itself
    if not new_event.event_type.startswith("anomaly_"):
        try:
            from wardline.incidents.service import IncidentService

            # We get all events from the repository up to a limit
            # "list_events con un límite interno de 500 y filtra por timestamp en memoria"
            history = state.events.list_events(limit=500)

            anomalies = state.anomaly.observe(
                new_event,
                history=history,
                open_incident=lambda **kwargs: IncidentService.open_if_needed(state, **kwargs),
            )
            for anomaly in anomalies:
                record_event(state, anomaly)
        except Exception:
            logging.getLogger("wardline.security").error("failed to observe anomaly", exc_info=True)
