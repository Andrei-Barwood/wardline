from typing import Any

from fastapi import APIRouter

from wardline.api.deps import LabState

router = APIRouter()


@router.get("/metrics")
async def get_metrics(state: LabState) -> dict[str, Any]:
    return state.metrics.to_dict()
