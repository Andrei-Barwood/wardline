import enum
from dataclasses import dataclass


class SimulationScenario(enum.StrEnum):
    burst = "burst"
    invalid_messages = "invalid_messages"
    connection_pressure = "connection_pressure"
    udp_burst = "udp_burst"
    all = "all"


class SimulationMode(enum.StrEnum):
    inprocess = "inprocess"
    loopback = "loopback"


@dataclass(frozen=True)
class SimulationResult:
    scenario: SimulationScenario
    mode: SimulationMode
    events_recorded: int
    refused: bool
    reason: str | None
    correlation_id: str


class SimulationRefused(Exception):
    def __init__(self, refused: bool, reason: str, correlation_id: str | None = None) -> None:
        super().__init__(reason)
        self.refused = refused
        self.reason = reason
        self.correlation_id = correlation_id
