"""Process entry point. The default mode starts HTTP, TCP, and UDP.

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
from wardline.logsetup import configure_logging
from wardline.runtime import AppState, build_state
from wardline.serve import RunningServer, start_http, start_tcp, start_udp


def main(argv: list[str] | None = None) -> int:
    """Start the local services, or print configuration when dry-run is set.

    --only defaults to all: HTTP, TCP, and UDP on loopback.
    """
    parser = argparse.ArgumentParser(prog="wardline")
    parser.add_argument("--only", choices=("http", "tcp", "udp", "all"), default="all")
    parsed = parser.parse_args() if argv is None else parser.parse_args(argv)
    if os.environ.get("WARDLINE_DRY_RUN") == "1":
        return _print_configured()
    try:
        settings = load_settings()
    except WardlineError as caught:
        print(caught.message, file=sys.stderr)
        return 2
    except ValidationError:
        print("invalid configuration", file=sys.stderr)
        return 2
    configure_logging(settings)
    asyncio.run(_serve(build_state(settings), parsed.only))
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


async def _serve(state: AppState, only: str) -> None:
    http: RunningServer | None = None
    tcp: RunningServer | None = None
    udp: RunningServer | None = None
    try:
        if only in {"http", "all"}:
            http = await start_http(state)
        if only in {"tcp", "all"}:
            tcp = await start_tcp(state)
        if only in {"udp", "all"}:
            udp = await start_udp(state)
        if http is not None and http.task is not None:
            await http.task
        else:
            await asyncio.Event().wait()
    finally:
        if udp is not None:
            await udp.stop()
        if tcp is not None:
            await tcp.stop()
        if http is not None and http.task is not None and not http.task.done():
            await http.stop()


if __name__ == "__main__":
    raise SystemExit(main())
