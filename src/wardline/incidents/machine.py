"""Incident state machine."""

from dataclasses import replace
from datetime import datetime

from wardline.contracts import ErrorCode, IncidentState
from wardline.errors import WardlineError
from wardline.incidents.models import Incident, IncidentAction


def transition(
    incident: Incident,
    action: str,
    *,
    actor: str,
    now: datetime,
    note: str = "",
) -> Incident:
    """Transition an incident to a new state and record the action.

    resolve moves to RECOVERING; IncidentService.resolve completes RESOLVED only after
    health verification, added in the recovery prompt.
    """
    to_state: IncidentState

    if action == "acknowledge":
        if incident.state != IncidentState.DETECTED:
            raise WardlineError(ErrorCode.invalid_state_transition, "invalid state transition")
        to_state = IncidentState.INVESTIGATING

    elif action == "contain":
        if incident.state != IncidentState.INVESTIGATING:
            raise WardlineError(ErrorCode.invalid_state_transition, "invalid state transition")
        to_state = IncidentState.CONTAINED

    elif action == "resolve":
        if incident.state == IncidentState.CONTAINED:
            to_state = IncidentState.RECOVERING
        elif incident.state == IncidentState.RECOVERING:
            to_state = IncidentState.RESOLVED
        else:
            raise WardlineError(ErrorCode.invalid_state_transition, "invalid state transition")

    else:
        raise WardlineError(ErrorCode.invalid_state_transition, "invalid state transition")

    new_action = IncidentAction(
        at=now,
        actor=actor,
        action=action,
        from_state=incident.state,
        to_state=to_state,
        detail=note,
    )

    return replace(
        incident,
        state=to_state,
        updated_at=now,
        actions=(*incident.actions, new_action),
    )
