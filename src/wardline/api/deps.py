"""FastAPI dependencies for the administration API."""

from collections.abc import Callable
from typing import Annotated, NoReturn

from fastapi import Depends
from starlette.requests import Request

from wardline.auth.policy import role_allows
from wardline.clients.identity import validate_client_id
from wardline.contracts import ErrorCode, Principal, Role, SecurityEvent, ServiceName, Severity
from wardline.errors import RateLimitedError, WardlineError
from wardline.runtime import AppState


def get_state(request: Request) -> AppState:
    """Return the process state stored on the application."""
    lab = getattr(request.app.state, "lab", None)
    if not isinstance(lab, AppState):
        raise WardlineError(ErrorCode.internal, "internal error")
    return lab


LabState = Annotated[AppState, Depends(get_state)]


def require_principal(request: Request) -> Principal:
    """Extract and validate the API key from Authorization Bearer or X-API-Key."""
    lab = get_state(request)
    correlation_id = getattr(request.state, "correlation_id", "unavailable")

    def _fail_auth(reason: str, source: str = "unknown") -> NoReturn:
        lab.metrics.bump("http", "unauthorized_total")
        lab.audit.append(
            SecurityEvent(
                timestamp=lab.clock.now(),
                source=source,
                service=ServiceName.AUTH,
                event_type="security_auth_failure",
                severity=Severity.LOW,
                simulation=False,
                action="rejected",
                correlation_id=correlation_id,
                details={"reason": reason},
            )
        )
        raise WardlineError(ErrorCode.unauthorized, "unauthorized")

    # Extract and validate optional X-Client-Id
    client_id_header = request.headers.get("x-client-id")
    validated_client_id: str | None = None
    if client_id_header is not None:
        try:
            validated_client_id = validate_client_id(client_id_header)
        except WardlineError:
            _fail_auth("mismatch", "unknown")

    effective_source = validated_client_id or "unknown"
    auth_header = request.headers.get("authorization")
    api_key_header = request.headers.get("x-api-key")

    token_from_auth: str | None = None
    if auth_header is not None:
        parts = auth_header.split(" ")
        if len(parts) != 2 or parts[0] != "Bearer" or not parts[1]:
            _fail_auth("mismatch" if auth_header.strip() else "missing", effective_source)
        token_from_auth = parts[1]

    token_from_api_key: str | None = None
    if api_key_header is not None:
        if not api_key_header:
            _fail_auth("missing", effective_source)
        token_from_api_key = api_key_header

    if token_from_auth is None and token_from_api_key is None:
        _fail_auth("missing", effective_source)

    if token_from_auth is not None and token_from_api_key is not None:
        if token_from_auth != token_from_api_key:
            _fail_auth("mismatch", effective_source)

    token = token_from_auth if token_from_auth is not None else token_from_api_key
    assert token is not None

    principal = lab.auth.authenticate_request(token, client_id=validated_client_id)
    if principal is None or not principal.authenticated:
        _fail_auth("mismatch", effective_source)

    return principal


PrincipalDep = Annotated[Principal, Depends(require_principal)]


def require_role(*allowed: Role) -> Callable[..., Principal]:
    """Return a dependency requiring that the principal has one of the allowed roles."""

    def dependency(
        request: Request,
        principal: PrincipalDep,
    ) -> Principal:
        lab = get_state(request)
        correlation_id = getattr(request.state, "correlation_id", "unavailable")
        if not any(role_allows(principal.role, req) for req in allowed):
            lab.metrics.bump("http", "forbidden_total")
            required_name = (
                allowed[0].value if len(allowed) == 1 else ",".join(r.value for r in allowed)
            )
            lab.audit.append(
                SecurityEvent(
                    timestamp=lab.clock.now(),
                    source=principal.client_id,
                    service=ServiceName.AUTH,
                    event_type="security_authz_denied",
                    severity=Severity.LOW,
                    simulation=False,
                    action="denied",
                    correlation_id=correlation_id,
                    details={"required": required_name},
                )
            )
            raise WardlineError(ErrorCode.forbidden, "forbidden")
        return principal

    return dependency



def check_rate_limit(request: Request, state: LabState) -> None:
    host = request.client.host if request.client is not None else "unknown"
    key = f"anon:{host}"
    
    # Extract client_id manually if authorized, because we can't easily access principal
    auth_header = request.headers.get("authorization")
    api_key_header = request.headers.get("x-api-key")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    elif api_key_header:
        token = api_key_header
        
    client_id_header = request.headers.get("x-client-id")
    
    if token:
        from wardline.clients.identity import validate_client_id
        from wardline.errors import WardlineError
        valid_client_id = None
        if client_id_header:
            try:
                valid_client_id = validate_client_id(client_id_header)
            except WardlineError:
                pass
        
        principal = state.auth.authenticate_request(token, client_id=valid_client_id)
        if principal and principal.authenticated:
            key = principal.client_id
            
    if not state.rate_limiter.allow(key):
        state.metrics.bump("http", "rate_limited_total")
        retry = state.rate_limiter.retry_after(key)
        raise RateLimitedError("rate limited", retry_after=retry, source=key)
