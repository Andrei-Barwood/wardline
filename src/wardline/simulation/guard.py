import uuid

from wardline.simulation.scenarios import SimulationRefused

SIMULATION_MAX_HEALTH_REQUESTS = 30
SIMULATION_MAX_INVALID_LINES = 8
SIMULATION_MAX_CONNECTIONS = 8
SIMULATION_MAX_DATAGRAMS = 20
SIMULATION_MAX_SECONDS = 2.0
SIMULATION_MAX_DATAGRAM_BYTES = 200


def assert_loopback(host: str) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise SimulationRefused(
            refused=True, reason="non_loopback_target", correlation_id=str(uuid.uuid4())
        )
