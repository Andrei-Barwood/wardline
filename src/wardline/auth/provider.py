"""Authentication provider protocol, test doubles, and API-key provider."""

from typing import Protocol

from wardline.auth.api_keys import ApiKeyRegistry
from wardline.contracts import Principal, Role


class AuthProvider(Protocol):
    def authenticate(self, token: str | None) -> Principal | None:
        """Return a principal, or None when the token is rejected."""

    def authenticate_request(
        self, token: str | None, client_id: str | None = None
    ) -> Principal | None:
        """Return an authenticated principal with the given client_id, or None."""


class AllowAllAuth:
    """Accept every caller as an unauthenticated viewer.

    Test double for scenarios that do not enforce API keys.
    """

    def authenticate(self, token: str | None) -> Principal | None:
        del token
        return Principal(client_id="anonymous", role=Role.VIEWER, authenticated=False)

    def authenticate_request(
        self, token: str | None, client_id: str | None = None
    ) -> Principal | None:
        del token
        return Principal(client_id=client_id or "anonymous", role=Role.VIEWER, authenticated=False)


class ApiKeyAuthProvider:
    """Authenticate tokens using the hashed laboratory keys."""

    def __init__(self, raw_keys: str) -> None:
        self.registry = ApiKeyRegistry(raw_keys)

    def authenticate_request(
        self, token: str | None, client_id: str | None = None
    ) -> Principal | None:
        role = self.registry.role_for_token(token)
        if role is None:
            return None
        effective_client_id = client_id if client_id is not None else f"api-{role.value}"
        return Principal(client_id=effective_client_id, role=role, authenticated=True)

    def authenticate(self, token: str | None) -> Principal | None:
        return self.authenticate_request(token, client_id=None)

