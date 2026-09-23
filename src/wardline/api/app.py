"""FastAPI application factory for the local administration API."""

import json
import uuid
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Receive, Scope, Send

from wardline.api.errors import (
    correlation_id_from,
    error_payload,
    status_for,
    wardline_error_payload,
)
from wardline.api.routes.health import router as health_router
from wardline.api.routes.status import router as status_router
from wardline.api.routes.version import router as version_router
from wardline.config.settings import load_settings
from wardline.contracts import ErrorCode
from wardline.errors import WardlineError
from wardline.runtime import AppState, build_state


class RequestContextMiddleware:
    """Assign a correlation id, count the request, and refuse oversized bodies."""

    def __init__(self, app: ASGIApp, lab: AppState) -> None:
        self.app = app
        self.lab = lab

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        correlation_id = str(uuid.uuid4())
        state = scope.setdefault("state", {})
        if isinstance(state, dict):
            state["correlation_id"] = correlation_id
        self.lab.metrics.bump("http", "requests_total")
        too_large = _content_length_too_large(scope, self.lab.settings.http_max_body_bytes)
        if too_large:
            await _send_json(
                send,
                status_code=413,
                payload=error_payload(
                    ErrorCode.validation_error,
                    "request body is too large",
                    correlation_id,
                ),
                correlation_id=correlation_id,
            )
            return

        async def send_with_correlation(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Correlation-ID"] = correlation_id
            await send(message)

        await self.app(scope, receive, send_with_correlation)


def create_app(state: AppState | None = None) -> FastAPI:
    """Build the administration app. TCP and UDP stay down until their servers start."""
    lab = build_state(load_settings()) if state is None else state
    _mark_local_health(lab)
    app = FastAPI(
        title="Wardline",
        description="Local defensive laboratory.",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.lab = lab
    app.add_middleware(RequestContextMiddleware, lab=lab)
    app.include_router(health_router)
    app.include_router(version_router)
    app.include_router(status_router)
    _install_handlers(app)
    return app


def _mark_local_health(state: AppState) -> None:
    state.health.set_status("http", "ok")
    try:
        state.events.list_events(limit=1)
    except Exception:
        state.health.set_status("database", "down")
    else:
        state.health.set_status("database", "ok")


def _install_handlers(app: FastAPI) -> None:
    @app.exception_handler(WardlineError)
    async def handle_domain(request: Any, exc: WardlineError) -> JSONResponse:
        correlation_id = correlation_id_from(request)
        return JSONResponse(
            status_code=status_for(exc.code),
            content=wardline_error_payload(exc, correlation_id),
        )

    @app.exception_handler(HTTPException)
    async def handle_http(request: Any, exc: HTTPException) -> JSONResponse:
        correlation_id = correlation_id_from(request)
        if exc.status_code == 404:
            code = ErrorCode.not_found
            message = "not found"
        else:
            code = ErrorCode.validation_error
            message = "request failed"
        return JSONResponse(
            status_code=exc.status_code,
            content=error_payload(code, message, correlation_id),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation(request: Any, exc: RequestValidationError) -> JSONResponse:
        del exc
        correlation_id = correlation_id_from(request)
        return JSONResponse(
            status_code=400,
            content=error_payload(ErrorCode.validation_error, "invalid request", correlation_id),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Any, exc: Exception) -> JSONResponse:
        del exc
        correlation_id = correlation_id_from(request)
        return JSONResponse(
            status_code=500,
            content=error_payload(ErrorCode.internal, "internal error", correlation_id),
        )


def _content_length_too_large(scope: Scope, limit: int) -> bool:
    for name, value in scope.get("headers", []):
        if name.lower() == b"content-length":
            try:
                size = int(value)
            except ValueError:
                return True
            return size > limit
    return False


async def _send_json(
    send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    *,
    status_code: int,
    payload: dict[str, Any],
    correlation_id: str,
) -> None:
    body = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"x-correlation-id", correlation_id.encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
