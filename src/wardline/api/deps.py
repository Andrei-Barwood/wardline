"""FastAPI dependencies for the administration API."""

from typing import Annotated

from fastapi import Depends
from starlette.requests import Request

from wardline.contracts import ErrorCode
from wardline.errors import WardlineError
from wardline.runtime import AppState


def get_state(request: Request) -> AppState:
    """Return the process state stored on the application."""
    lab = getattr(request.app.state, "lab", None)
    if not isinstance(lab, AppState):
        raise WardlineError(ErrorCode.internal, "internal error")
    return lab


LabState = Annotated[AppState, Depends(get_state)]
