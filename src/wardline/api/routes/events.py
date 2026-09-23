from fastapi import APIRouter, Depends
from pydantic import BaseModel

from wardline.api.deps import LabState, require_role
from wardline.contracts import Role, SecurityEvent, ServiceName, Severity

router = APIRouter()


class ListEventsResponse(BaseModel):
    events: list[SecurityEvent]


@router.get(
    "/events", response_model=ListEventsResponse, dependencies=[Depends(require_role(Role.VIEWER))]
)
def list_events(
    state: LabState,
    limit: int = 100,
    min_severity: Severity | None = None,
    service: ServiceName | None = None,
    simulation: bool | None = None,
) -> ListEventsResponse:
    events = state.events.list_events(
        limit=limit,
        min_severity=min_severity,
        service=service,
        simulation=simulation,
    )
    return ListEventsResponse(events=events)
