"""Process entry point. The default mode is HTTP until TCP and UDP exist.

Prompt 05 changes the default of --only to all.
WARDLINE_DRY_RUN=1 prints bindings and does not open a socket.
"""

import argparse
import asyncio
import json
import os
import sys

from pydantic import ValidationError

from wardline.config.settings import Settings, load_settings
from wardline.errors import WardlineError
from wardline.runtime import AppState, build_state
from wardline.serve import start_http


def main(argv: list[str] | None = None) -> int:
    """Start the local HTTP API, or print configuration when dry-run is set.

    --only defaults to http because the TCP and UDP servers are not part of
    this prompt yet. Prompt 05 changes that default to all.
    """
    parser = argparse.ArgumentParser(prog="wardline")
    parser.add_argument("--only", choices=("http", "tcp", "udp", "all"), default="http")
    parsed = parser.parse_args() if argv is None else parser.parse_args(argv)
    if os.environ.get("WARDLINE_DRY_RUN") == "1":
        return _print_configured()
    if parsed.only in {"tcp", "udp"}:
        print(f"{parsed.only} service is not available yet", file=sys.stderr)
        return 2
    try:
        settings = load_settings()
    except WardlineError as caught:
        print(caught.message, file=sys.stderr)
        return 2
    except ValidationError:
        print("invalid configuration", file=sys.stderr)
        return 2
    asyncio.run(_serve_http(build_state(settings)))
    return 0


def _print_configured() -> int:
    try:
        settings = load_settings()
    except WardlineError as caught:
        print(caught.message, file=sys.stderr)
        return 2
    except ValidationError:
        print("invalid configuration", file=sys.stderr)
        return 2
    print(_bindings_line(settings))
    return 0


def _bindings_line(settings: Settings) -> str:
    payload = {
        "status": "configured",
        "bindings": {
            "http": f"{settings.http_host}:{settings.http_port}",
            "tcp": f"{settings.tcp_host}:{settings.tcp_port}",
            "udp": f"{settings.udp_host}:{settings.udp_port}",
        },
    }
    return json.dumps(payload, separators=(",", ":"))


async def _serve_http(state: AppState) -> None:
    running = await start_http(state)
    await running.task


if __name__ == "__main__":
    raise SystemExit(main())
