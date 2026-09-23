"""GET /version. Public. Reads the package version."""

from fastapi import APIRouter

from wardline import __version__

router = APIRouter()


@router.get("/version")
def read_version() -> dict[str, str]:
    """Return the running package name and version."""
    return {"name": "wardline", "version": __version__}
