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


class RateLimitedError(WardlineError):
    def __init__(self, message: str, retry_after: int, source: str) -> None:
        super().__init__(ErrorCode.rate_limited, message)
        self.retry_after = retry_after
        self.source = source
