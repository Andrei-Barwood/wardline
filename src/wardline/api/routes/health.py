"""GET /health. Public. Degraded when any critical component is down."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from wardline.api.deps import LabState

router = APIRouter()

_COMPONENTS = ("http", "tcp", "udp", "database")


@router.get("/health")
def read_health(state: LabState) -> JSONResponse:
    """Report component health without secrets."""
    snapshot = state.health.snapshot()
    checks = {name: snapshot.get(name, "down") for name in _COMPONENTS}
    healthy = all(value == "ok" for value in checks.values())
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={"status": "ok" if healthy else "degraded", "checks": checks},
    )
