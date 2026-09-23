"""Unit tests for role hierarchy and TCP command authorization mapping."""

from wardline.auth.policy import TCP_COMMAND_MIN_ROLE, role_allows
from wardline.contracts import Role
from wardline.tcp.protocol import ALLOWED_TYPES


def test_role_hierarchy() -> None:
    # Admin fulfills all roles
    assert role_allows(Role.ADMIN, Role.ADMIN) is True
    assert role_allows(Role.ADMIN, Role.OPERATOR) is True
    assert role_allows(Role.ADMIN, Role.VIEWER) is True

    # Operator fulfills operator and viewer
    assert role_allows(Role.OPERATOR, Role.ADMIN) is False
    assert role_allows(Role.OPERATOR, Role.OPERATOR) is True
    assert role_allows(Role.OPERATOR, Role.VIEWER) is True

    # Viewer fulfills only viewer
    assert role_allows(Role.VIEWER, Role.ADMIN) is False
    assert role_allows(Role.VIEWER, Role.OPERATOR) is False
    assert role_allows(Role.VIEWER, Role.VIEWER) is True


def test_tcp_types_are_all_authorized() -> None:
    # Every type parsed by the TCP protocol must be declared in TCP_COMMAND_MIN_ROLE
    assert ALLOWED_TYPES == set(TCP_COMMAND_MIN_ROLE.keys())
    for command_type in ALLOWED_TYPES:
        assert command_type in TCP_COMMAND_MIN_ROLE
        assert isinstance(TCP_COMMAND_MIN_ROLE[command_type], Role)
