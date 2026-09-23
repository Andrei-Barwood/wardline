import argparse
import asyncio
import json
import sys

from wardline.config import load_settings
from wardline.runtime import build_state
from wardline.simulation.engine import (
    simulate_all,
    simulate_burst,
    simulate_connection_pressure,
    simulate_invalid_messages,
    simulate_udp_burst,
)
from wardline.simulation.scenarios import SimulationMode, SimulationScenario


async def main() -> None:
    parser = argparse.ArgumentParser(description="Wardline Simulation Engine")
    parser.add_argument(
        "--scenario", type=SimulationScenario, choices=list(SimulationScenario), required=True
    )
    parser.add_argument("--mode", type=SimulationMode, choices=list(SimulationMode), required=True)

    args = parser.parse_args()

    settings = load_settings()
    state = build_state(settings)

    if args.mode == SimulationMode.loopback:
        if settings.http_port == 0 and settings.tcp_port == 0 and settings.udp_port == 0:
            print("Mode loopback sin servicios", file=sys.stderr)
            sys.exit(2)

    if args.scenario == SimulationScenario.burst:
        result = await simulate_burst(state, mode=args.mode)
    elif args.scenario == SimulationScenario.invalid_messages:
        result = await simulate_invalid_messages(state, mode=args.mode)
    elif args.scenario == SimulationScenario.connection_pressure:
        result = await simulate_connection_pressure(state, mode=args.mode)
    elif args.scenario == SimulationScenario.udp_burst:
        result = await simulate_udp_burst(state, mode=args.mode)
    elif args.scenario == SimulationScenario.all:
        result = await simulate_all(state, mode=args.mode)
    else:
        sys.exit(2)

    out = {
        "scenario": result.scenario.value,
        "mode": result.mode.value,
        "events_recorded": result.events_recorded,
        "refused": result.refused,
    }
    print(json.dumps(out))
    if result.refused:
        sys.exit(3)
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
