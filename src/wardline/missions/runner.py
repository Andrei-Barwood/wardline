"""Runner for executing mission checks safely."""

import logging
from collections.abc import Callable, Coroutine
from typing import Any

from wardline.contracts import ErrorCode
from wardline.errors import WardlineError
from wardline.logsetup import get_logger
from wardline.missions.catalog import get_mission
from wardline.missions.checks import (
    check_m01,
    check_m02,
    check_m03,
    check_m04,
    check_m05,
)
from wardline.missions.models import MissionResult
from wardline.runtime import AppState

logger = get_logger(__name__)

_CHECKS: dict[str, Callable[[AppState], Coroutine[Any, Any, MissionResult]]] = {
    "m01": check_m01,
    "m02": check_m02,
    "m03": check_m03,
    "m04": check_m04,
    "m05": check_m05,
}


async def run_check(state: AppState, mission_id: str) -> MissionResult:
    """Run the automated check for a mission by id."""
    mission = get_mission(mission_id)
    if mission is None:
        raise WardlineError(ErrorCode.not_found, f"mission '{mission_id}' not found")

    check_fn = _CHECKS.get(mission_id)
    if check_fn is None:
        raise WardlineError(ErrorCode.not_found, f"mission '{mission_id}' has no check")

    try:
        return await check_fn(state)
    except Exception as exc:
        logging.getLogger("wardline").error(
            "mission check failed with unexpected exception",
            exc_info=False,
            extra={"mission_id": mission_id, "error": str(exc)},
        )
        return MissionResult(
            mission_id=mission_id,
            passed=False,
            observations=("check failed",),
        )
