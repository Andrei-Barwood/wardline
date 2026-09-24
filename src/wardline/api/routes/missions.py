"""API routes for educational missions."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from wardline.api.deps import LabState, require_role
from wardline.contracts import ErrorCode, Principal, Role
from wardline.errors import WardlineError
from wardline.missions.catalog import MISSIONS, get_mission
from wardline.missions.runner import run_check

router = APIRouter()

ViewerPrincipal = Annotated[Principal, Depends(require_role(Role.VIEWER))]
OperatorPrincipal = Annotated[Principal, Depends(require_role(Role.OPERATOR))]


@router.get("/missions")
async def list_missions(_: ViewerPrincipal) -> dict[str, Any]:
    """Return a compact summary of available missions."""
    return {
        "missions": [
            {
                "id": m.id,
                "chapter": m.chapter,
                "title": m.title,
                "objective": m.objective,
            }
            for m in MISSIONS
        ]
    }


@router.get("/missions/{mission_id}")
async def get_mission_detail(mission_id: str, _: ViewerPrincipal) -> dict[str, Any]:
    """Return complete details for a single mission."""
    mission = get_mission(mission_id)
    if mission is None:
        raise WardlineError(ErrorCode.not_found, f"mission '{mission_id}' not found")

    return {
        "id": mission.id,
        "chapter": mission.chapter,
        "title": mission.title,
        "objective": mission.objective,
        "context": mission.context,
        "concept": mission.concept,
        "required_action": mission.required_action,
        "expected_result": mission.expected_result,
        "explanation": mission.explanation,
    }


@router.post("/missions/{mission_id}/check")
async def check_mission(
    mission_id: str,
    state: LabState,
    _: OperatorPrincipal,
) -> dict[str, Any]:
    """Execute automated local verification for a mission."""
    mission = get_mission(mission_id)
    if mission is None:
        raise WardlineError(ErrorCode.not_found, f"mission '{mission_id}' not found")

    result = await run_check(state, mission_id)
    return {
        "mission_id": result.mission_id,
        "passed": result.passed,
        "observations": list(result.observations),
        "explanation": mission.explanation,
    }
