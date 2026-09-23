"""Local size and capacity checks shared by the transports."""

from wardline.contracts import ErrorCode
from wardline.errors import WardlineError


def check_message_size(n: int, limit: int) -> None:
    """Reject a frame that is larger than the configured maximum."""
    if n > limit:
        raise WardlineError(ErrorCode.message_too_large, "message too large")


def check_connection_capacity(active: int, limit: int) -> None:
    """Reject a new session when the process is already at the connection cap."""
    if active >= limit:
        raise WardlineError(ErrorCode.connection_limit, "connection limit")
