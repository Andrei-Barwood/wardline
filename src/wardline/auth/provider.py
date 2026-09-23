"""Authentication provider protocol and the temporary open provider."""

from typing import Protocol

from wardline.contracts import Principal, Role


class AuthProvider(Protocol):
    def authenticate(self, token: str | None) -> Principal | None:
        """Return a principal, or None when the token is rejected."""


class AllowAllAuth:
    """Accept every caller as an unauthenticated viewer.

    Prompt 07 replaces this provider with API-key authentication.
    The token is not checked and is not stored.
    """

    def authenticate(self, token: str | None) -> Principal | None:
        del token
        return Principal(client_id="anonymous", role=Role.VIEWER, authenticated=False)
