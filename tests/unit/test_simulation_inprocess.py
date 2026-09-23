import subprocess
import sys

import pytest

from wardline.config import Settings
from wardline.runtime import build_state
from wardline.simulation.engine import (
    simulate_all,
    simulate_burst,
)
from wardline.simulation.scenarios import SimulationMode


@pytest.mark.asyncio
async def test_each_scenario_event_type_and_flag():
    state = build_state(Settings(wardline_env="test"))
    await simulate_burst(state, mode=SimulationMode.inprocess)

    events = state.events.list_events(limit=10)
    assert len(events) == 5
    for ev in events:
        assert ev.event_type == "simulated_rate_abuse"
        assert ev.simulation is True
        assert ev.details["synthetic"] is True


@pytest.mark.asyncio
async def test_simulate_all_runs_four():
    state = build_state(Settings(wardline_env="test"))
    result = await simulate_all(state, mode=SimulationMode.inprocess)
    events = state.events.list_events(limit=100)
    assert len(events) == 16
    assert result.events_recorded == 16


def test_cli_inprocess_exit_zero():
    res = subprocess.run(
        [sys.executable, "-m", "wardline.simulation", "--scenario", "burst", "--mode", "inprocess"],
        capture_output=True,
    )
    assert res.returncode == 0
