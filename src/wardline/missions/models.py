"""Data models for defensive missions."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Mission:
    """A structured educational mission explaining a defensive concept."""

    id: str
    chapter: int
    title: str
    objective: str
    context: str
    concept: str
    required_action: str
    expected_result: str
    explanation: str


@dataclass(frozen=True)
class MissionResult:
    """The outcome of running a local mission check."""

    mission_id: str
    passed: bool
    observations: tuple[str, ...]
