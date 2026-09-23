from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

from wardline.api.deps import LabState, require_role
from wardline.contracts import Role
from wardline.simulation.engine import (
    simulate_all,
    simulate_burst,
    simulate_connection_pressure,
    simulate_invalid_messages,
    simulate_udp_burst,
)
from wardline.simulation.scenarios import SimulationMode, SimulationResult, SimulationScenario

router = APIRouter()


class SimulationRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: SimulationScenario
    mode: SimulationMode


@router.post("/simulation/run", dependencies=[Depends(require_role(Role.OPERATOR))])
async def run_simulation(request: SimulationRunRequest, state: LabState) -> SimulationResult:
    if request.scenario == SimulationScenario.burst:
        return await simulate_burst(state, mode=request.mode)
    elif request.scenario == SimulationScenario.invalid_messages:
        return await simulate_invalid_messages(state, mode=request.mode)
    elif request.scenario == SimulationScenario.connection_pressure:
        return await simulate_connection_pressure(state, mode=request.mode)
    elif request.scenario == SimulationScenario.udp_burst:
        return await simulate_udp_burst(state, mode=request.mode)
    else:
        return await simulate_all(state, mode=request.mode)
