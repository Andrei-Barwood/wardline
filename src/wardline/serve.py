"""Start and stop the local HTTP server. TCP and UDP arrive in later prompts."""

import asyncio
from dataclasses import dataclass

import uvicorn

from wardline.api.app import create_app
from wardline.runtime import AppState


@dataclass
class RunningServer:
    """A server that is already accepting connections on loopback."""

    server: uvicorn.Server
    port: int
    task: asyncio.Task[None]

    async def stop(self) -> None:
        """Ask the server to leave its loop and wait until the socket is closed."""
        self.server.should_exit = True
        await asyncio.wait_for(self.task, timeout=5)


async def start_http(state: AppState) -> RunningServer:
    """Bind the administration API to the configured loopback host."""
    app = create_app(state)
    config = uvicorn.Config(
        app,
        host=state.settings.http_host,
        port=state.settings.http_port,
        access_log=False,
        log_config=None,
        log_level="warning",
        lifespan="off",
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        await _wait_until_started(server, task)
    except Exception:
        server.should_exit = True
        if not task.done():
            task.cancel()
        raise
    bound = server.servers[0].sockets
    if not bound:
        raise RuntimeError("http server has no listening socket")
    port = int(bound[0].getsockname()[1])
    state.bindings["http"] = f"{state.settings.http_host}:{port}"
    return RunningServer(server=server, port=port, task=task)


async def _wait_until_started(server: uvicorn.Server, task: asyncio.Task[None]) -> None:
    for _ in range(100):
        if server.started and getattr(server, "servers", None):
            sockets = server.servers[0].sockets
            if sockets:
                return
        if task.done():
            task.result()
            raise RuntimeError("http server stopped before accepting connections")
        await asyncio.sleep(0.02)
    raise RuntimeError("http server did not start")
