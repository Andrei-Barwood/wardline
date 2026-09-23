"""Authorization policy and role hierarchy."""

from wardline.contracts import Role

_ROLE_POWER: dict[Role, int] = {
    Role.VIEWER: 1,
    Role.OPERATOR: 2,
    Role.ADMIN: 3,
}

TCP_COMMAND_MIN_ROLE: dict[str, Role] = {
    "hello": Role.VIEWER,
    "ping": Role.VIEWER,
    "echo": Role.VIEWER,
    "status": Role.VIEWER,
    "bye": Role.VIEWER,
}


def role_allows(actual: Role, required: Role) -> bool:
    """Return True if actual role meets or exceeds the required role."""
    actual_power = _ROLE_POWER.get(actual, 0)
    required_power = _ROLE_POWER.get(required, 999)
    return actual_power >= required_power
