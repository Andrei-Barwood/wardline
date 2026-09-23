"""Client identifiers accepted by the local laboratory."""

import re

from wardline.contracts import ErrorCode
from wardline.errors import WardlineError

_CLIENT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def validate_client_id(value: object) -> str:
    """Return the client id, or raise invalid_message when it is not allowed."""
    if not isinstance(value, str) or _CLIENT_ID.fullmatch(value) is None:
        raise WardlineError(ErrorCode.invalid_message, "invalid client id")
    return value
