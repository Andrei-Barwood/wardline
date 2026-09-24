from typing import Any

from fastapi import APIRouter

from wardline.api.deps import LabState
from wardline.contracts import ErrorCode, IncidentState, ServiceName, Severity
from wardline.errors import WardlineError

router = APIRouter()


@router.get("/security/summary")
async def get_security_summary(state: LabState) -> dict[str, Any]:
    try:
        events_to_inspect = state.events.list_events(limit=5001)
    except Exception:
        raise WardlineError(ErrorCode.internal, "internal error") from None

    truncated = False
    if len(events_to_inspect) > 5000:
        truncated = True
        events_to_inspect = events_to_inspect[:5000]

    by_severity = {s.value: 0 for s in Severity}
    by_service = {s.value: 0 for s in ServiceName}
    simulation_events = 0

    for e in events_to_inspect:
        if e.severity.value in by_severity:
            by_severity[e.severity.value] += 1
        if e.service.value in by_service:
            by_service[e.service.value] += 1
        if e.simulation:
            simulation_events += 1

    try:
        open_incidents = sum(
            1 for incident in state.incidents.list_all() if incident.state != IncidentState.RESOLVED
        )
    except Exception:
        raise WardlineError(ErrorCode.internal, "internal error") from None

    active_blocks = state.blocks.count_active(state.clock.now())

    return {
        "by_severity": by_severity,
        "by_service": by_service,
        "open_incidents": open_incidents,
        "active_blocks": active_blocks,
        "simulation_events": simulation_events,
        "truncated": truncated,
    }
