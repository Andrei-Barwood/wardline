"""JSON error bodies for the administration API. Responses never include tracebacks."""

from typing import Any

from starlette.requests import Request

from wardline.contracts import ErrorCode
from wardline.errors import WardlineError


def error_payload(
    code: ErrorCode,
    message: str,
    correlation_id: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the stable error document."""
    doc: dict[str, Any] = {
        "error": {
            "code": code.value,
            "message": message,
            "correlation_id": correlation_id,
        }
    }
    if details is not None:
        doc["error"]["details"] = details
    return doc


def correlation_id_from(request: Request) -> str:
    """Return the id set by middleware, or a placeholder if the request never reached it."""
    value = getattr(request.state, "correlation_id", None)
    if isinstance(value, str) and value:
        return value
    return "unavailable"


def status_for(code: ErrorCode) -> int:
    """Map a domain code to an HTTP status. Unknown codes fail closed as 400."""
    return {
        ErrorCode.unauthorized: 401,
        ErrorCode.forbidden: 403,
        ErrorCode.client_blocked: 403,
        ErrorCode.not_found: 404,
        ErrorCode.invalid_state_transition: 409,
        ErrorCode.rate_limited: 429,
        ErrorCode.quota_exceeded: 429,
        ErrorCode.circuit_open: 503,
        ErrorCode.internal: 500,
    }.get(code, 400)


def wardline_error_payload(error: WardlineError, correlation_id: str) -> dict[str, Any]:
    """Public message for a domain error. Internal failures stay generic."""
    details = getattr(error, "details", None)
    if error.code == ErrorCode.internal:
        return error_payload(ErrorCode.internal, "internal error", correlation_id)
    return error_payload(
        error.code,
        error.message,
        correlation_id,
        details=details if isinstance(details, dict) else None,
    )
