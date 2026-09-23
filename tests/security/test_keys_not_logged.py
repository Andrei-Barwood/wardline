"""Security test: ensure keys never appear in log files or audit logs."""

import asyncio
import io
import json
from collections.abc import Callable
from pathlib import Path

from wardline.audit.log import FileAuditLog
from wardline.config.settings import Settings
from wardline.logsetup import configure_logging
from wardline.runtime import build_state
from wardline.serve import start_tcp


async def _open(port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection("127.0.0.1", port)


async def _send(writer: asyncio.StreamWriter, payload: dict[str, object]) -> None:
    writer.write(json.dumps(payload).encode("utf-8") + b"\n")
    await writer.drain()


async def _read(reader: asyncio.StreamReader, timeout: float = 1.0) -> dict[str, object]:
    line = await asyncio.wait_for(reader.readline(), timeout)
    assert line
    parsed = json.loads(line)
    assert isinstance(parsed, dict)
    return parsed


async def test_log_file_has_no_key_after_failed_and_successful_hello(
    tmp_path: Path,
    settings_factory: Callable[..., Settings],
) -> None:
    log_stream = io.StringIO()
    settings = settings_factory()
    configure_logging(settings, stream=log_stream, replace=True)

    audit_path = tmp_path / "audit.jsonl"
    audit = FileAuditLog(
        path=audit_path,
        secrets=["dev-viewer-key", "dev-operator-key", "dev-admin-key"],
    )
    state = build_state(settings)
    state.audit = audit

    running = await start_tcp(state)
    try:
        # Failed hello with bogus key
        bogus_key = "dev-admin-key-nope"
        reader1, writer1 = await _open(running.port)
        await _send(writer1, {"type": "hello", "client_id": "test-client", "token": bogus_key})
        err = await _read(reader1)
        assert err["type"] == "error"
        writer1.close()
        await writer1.wait_closed()

        # Successful hello with admin key
        reader2, writer2 = await _open(running.port)
        await _send(
            writer2,
            {"type": "hello", "client_id": "admin-client", "token": "dev-admin-key"},
        )
        welcome = await _read(reader2)
        assert welcome["type"] == "welcome"
        writer2.close()
        await writer2.wait_closed()

        # Inspect application logs
        app_log_text = log_stream.getvalue()
        for forbidden in ("dev-viewer-key", "dev-operator-key", "dev-admin-key", bogus_key):
            assert forbidden not in app_log_text

        # Inspect audit logs
        assert audit_path.exists()
        audit_text = audit_path.read_text(encoding="utf-8")
        for forbidden in ("dev-viewer-key", "dev-operator-key", "dev-admin-key", bogus_key):
            assert forbidden not in audit_text
    finally:
        await running.stop()
