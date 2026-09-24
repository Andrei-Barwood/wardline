from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from wardline.api.deps import LabState, require_role
from wardline.contracts import Principal, Role
from wardline.incidents.models import Incident
from wardline.incidents.service import IncidentService, validate_incident_id

router = APIRouter()

OperatorPrincipal = Annotated[Principal, Depends(require_role(Role.OPERATOR))]
AdminPrincipal = Annotated[Principal, Depends(require_role(Role.ADMIN))]


class ActionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str = Field(default="", max_length=200)


def incident_to_dict(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "state": incident.state.value,
        "title": incident.title,
        "source": incident.source,
        "service": incident.service.value,
        "severity": incident.severity.value,
        "correlation_id": incident.correlation_id,
        "simulation": incident.simulation,
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
        "actions": [
            {
                "at": a.at.isoformat(),
                "actor": a.actor,
                "action": a.action,
                "from_state": a.from_state.value,
                "to_state": a.to_state.value,
                "detail": a.detail,
            }
            for a in incident.actions
        ],
    }


@router.get("/incidents")
async def list_incidents(state: LabState) -> dict[str, Any]:
    service = IncidentService(state)
    incidents = service.list_all()
    return {"incidents": [incident_to_dict(inc) for inc in incidents]}


@router.get("/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    state: LabState,
) -> dict[str, Any]:
    validate_incident_id(incident_id)
    service = IncidentService(state)
    incident = service.get(incident_id)
    return incident_to_dict(incident)


@router.post("/incidents/{incident_id}/acknowledge")
async def acknowledge_incident(
    incident_id: str,
    state: LabState,
    principal: OperatorPrincipal,
    payload: ActionPayload | None = None,
) -> dict[str, Any]:
    validate_incident_id(incident_id)
    service = IncidentService(state)
    note = payload.note if payload is not None else ""
    updated = service.acknowledge(incident_id, actor=principal.client_id, note=note)
    return incident_to_dict(updated)


@router.post("/incidents/{incident_id}/contain")
async def contain_incident(
    incident_id: str,
    state: LabState,
    principal: AdminPrincipal,
    payload: ActionPayload | None = None,
) -> dict[str, Any]:
    validate_incident_id(incident_id)
    service = IncidentService(state)
    note = payload.note if payload is not None else ""
    updated = service.contain(incident_id, actor=principal.client_id, note=note)
    return incident_to_dict(updated)


@router.post("/incidents/{incident_id}/resolve")
async def resolve_incident(
    incident_id: str,
    state: LabState,
    principal: AdminPrincipal,
    payload: ActionPayload | None = None,
) -> dict[str, Any]:
    validate_incident_id(incident_id)
    service = IncidentService(state)
    note = payload.note if payload is not None else ""
    updated = service.resolve(incident_id, actor=principal.client_id, note=note)
    return incident_to_dict(updated)
