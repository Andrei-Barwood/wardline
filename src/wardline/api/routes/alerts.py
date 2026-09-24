from typing import Annotated, Any

from fastapi import APIRouter, Query

from wardline.api.deps import LabState
from wardline.contracts import Severity
from wardline.monitoring.alerts import select_alerts

router = APIRouter()


@router.get("/alerts")
async def get_alerts(
    state: LabState,
    min_severity: Severity = Severity.LOW,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    events = state.events.list_events(limit=5000, min_severity=min_severity)
    alerts = select_alerts(events, min_severity=min_severity)[:limit]
    return {"alerts": alerts}
