"""GET /status. Public until authentication arrives in a later prompt."""

from fastapi import APIRouter

from wardline import __version__
from wardline.api.deps import LabState

router = APIRouter()

_COMPONENTS = ("http", "tcp", "udp", "database")


@router.get("/status")
def read_status(state: LabState) -> dict[str, object]:
    """Return process status. Bindings and components only; never keys."""
    snapshot = state.health.snapshot()
    return {
        "app": state.settings.app_name,
        "version": __version__,
        "environment": state.settings.environment,
        "started_at": state.started_at.isoformat(),
        "components": {name: snapshot.get(name, "down") for name in _COMPONENTS},
        "bindings": {
            "http": state.bindings["http"],
            "tcp": state.bindings["tcp"],
            "udp": state.bindings["udp"],
        },
    }
