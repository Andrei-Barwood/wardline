"""Stable errors raised inside the Wardline process."""

from wardline.contracts import ErrorCode


class WardlineError(Exception):
    """Domain error that later prompts map to an HTTP or protocol response."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class SimulationRefused(WardlineError):
    """The simulation engine refused to leave the local laboratory."""
