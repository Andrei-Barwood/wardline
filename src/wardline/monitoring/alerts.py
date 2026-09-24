from collections.abc import Sequence

from wardline.contracts import SEVERITY_RANK, SecurityEvent, Severity


def select_alerts(
    events: Sequence[SecurityEvent], *, min_severity: Severity
) -> list[SecurityEvent]:
    alerts = []
    min_rank = SEVERITY_RANK[min_severity]
    for e in events:
        if e.event_type.startswith("anomaly_") or e.event_type.startswith("security_"):
            if SEVERITY_RANK[e.severity] >= min_rank:
                alerts.append(e)
    return alerts
