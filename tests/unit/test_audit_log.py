"""Unit tests for the append-only audit log and event coalescing."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from wardline.audit.log import FileAuditLog, MemoryAuditLog
from wardline.contracts import SecurityEvent, ServiceName, Severity


class FakeClock:
    """Controllable clock for testing windows and timeouts."""

    def __init__(self, start: datetime | None = None) -> None:
        self._current = start or datetime.now(UTC)

    def now(self) -> datetime:
        return self._current

    def advance(self, seconds: float) -> None:
        self._current += timedelta(seconds=seconds)


def _make_event(clock: FakeClock, index: int) -> SecurityEvent:
    return SecurityEvent(
        timestamp=clock.now(),
        source="unit-test",
        service=ServiceName.MONITORING,
        event_type="test_event",
        severity=Severity.INFO,
        simulation=False,
        action="recorded",
        correlation_id=f"00000000-0000-4000-8000-{index:012d}",
        details={"seq": index},
    )


def test_audit_writes_jsonl(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    clock = FakeClock()
    audit = FileAuditLog(path=log_path, clock=clock)

    event = _make_event(clock, 1)
    audit.append(event)

    assert log_path.exists()
    lines = [line.strip() for line in log_path.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 1

    parsed = json.loads(lines[0])
    assert parsed["event_type"] == "test_event"
    assert parsed["source"] == "unit-test"
    assert parsed["service"] == "monitoring"
    assert parsed["correlation_id"] == "00000000-0000-4000-8000-000000000001"


def test_audit_coalesces_when_threshold_exceeded(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    clock = FakeClock()
    threshold = 5
    audit = FileAuditLog(
        path=log_path,
        clock=clock,
        threshold=threshold,
        window_seconds=1.0,
    )

    # Emit 10 events within the first second window
    for i in range(10):
        audit.append(_make_event(clock, i))

    # Advance time beyond the window to close it, and send another event
    clock.advance(1.5)
    audit.append(_make_event(clock, 10))

    lines = [line.strip() for line in log_path.read_text(encoding="utf-8").splitlines() if line]
    # We sent 11 events in total; lines must be strictly less than 11
    assert len(lines) < 11

    records = [json.loads(line) for line in lines]
    coalesced = [r for r in records if r.get("event_type") == "security_log_volume"]
    assert len(coalesced) == 1
    assert coalesced[0]["severity"] == "HIGH"
    assert coalesced[0]["service"] == "monitoring"
    assert coalesced[0]["action"] == "coalesced"
    assert coalesced[0]["details"]["dropped_count"] == 5


def test_memory_audit_log_coalescing() -> None:
    clock = FakeClock()
    threshold = 5
    audit = MemoryAuditLog(
        clock=clock,
        threshold=threshold,
        window_seconds=1.0,
    )

    for i in range(10):
        audit.append(_make_event(clock, i))

    clock.advance(1.5)
    audit.append(_make_event(clock, 10))

    assert len(audit.events) < 11
    coalesced = [e for e in audit.events if e.event_type == "security_log_volume"]
    assert len(coalesced) == 1
    assert coalesced[0].details["dropped_count"] == 5
