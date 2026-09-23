"""Append-only audit log. High volume collapses into one summary event."""

import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from wardline.contracts import Clock, SecurityEvent, ServiceName, Severity, SystemClock
from wardline.security.redaction import redact

AUDIT_COALESCE_THRESHOLD = 1000


class AuditLog(Protocol):
    def append(self, event: SecurityEvent) -> None:
        """Record one security event."""


class NullAuditLog:
    """Discard audit events."""

    def append(self, event: SecurityEvent) -> None:
        del event


class _Coalescer:
    """Count events inside a window and collapse the overflow into one record."""

    def __init__(self, *, clock: Clock, threshold: int, window_seconds: float) -> None:
        self._clock = clock
        self._threshold = threshold
        self._window = timedelta(seconds=window_seconds)
        self._window_started: datetime | None = None
        self._count = 0
        self._dropped = 0

    def observe(self, now: datetime) -> SecurityEvent | None:
        """Return a summary when the previous window has closed, else None."""
        if self._window_started is None:
            self._window_started = now
            return None
        if now - self._window_started < self._window:
            return None
        summary = self._summary(now)
        self._window_started = now
        self._count = 0
        self._dropped = 0
        return summary

    def keep_original(self) -> bool:
        self._count += 1
        if self._count <= self._threshold:
            return True
        self._dropped += 1
        return False

    def flush(self, now: datetime) -> SecurityEvent | None:
        summary = self._summary(now)
        self._window_started = now
        self._count = 0
        self._dropped = 0
        return summary

    def _summary(self, now: datetime) -> SecurityEvent | None:
        if self._dropped <= 0:
            return None
        return SecurityEvent(
            timestamp=now,
            source="system",
            service=ServiceName.MONITORING,
            event_type="security_log_volume",
            severity=Severity.HIGH,
            simulation=False,
            action="coalesced",
            correlation_id=str(uuid.uuid4()),
            details={"dropped_count": self._dropped},
        )


class MemoryAuditLog:
    """In-memory audit sink for tests."""

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        threshold: int = AUDIT_COALESCE_THRESHOLD,
        window_seconds: float = 1.0,
        secrets: Iterable[str] = (),
    ) -> None:
        self.events: list[SecurityEvent] = []
        self._secrets = tuple(secrets)
        self._coalescer = _Coalescer(
            clock=clock or SystemClock(),
            threshold=threshold,
            window_seconds=window_seconds,
        )
        self._clock = clock or SystemClock()

    def append(self, event: SecurityEvent) -> None:
        now = self._clock.now()
        summary = self._coalescer.observe(now)
        if summary is not None:
            self.events.append(summary)
        if self._coalescer.keep_original():
            self.events.append(_redact_event(event, self._secrets))

    def flush(self) -> None:
        now = self._clock.now()
        summary = self._coalescer.flush(now)
        if summary is not None:
            self.events.append(summary)


class FileAuditLog:
    """JSONL audit file under the laboratory data directory."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        clock: Clock | None = None,
        threshold: int = AUDIT_COALESCE_THRESHOLD,
        window_seconds: float = 1.0,
        secrets: Iterable[str] = (),
    ) -> None:
        self.path = path or Path("data/logs/audit.jsonl")
        self._secrets = tuple(secrets)
        self._clock = clock or SystemClock()
        self._coalescer = _Coalescer(
            clock=self._clock,
            threshold=threshold,
            window_seconds=window_seconds,
        )

    def append(self, event: SecurityEvent) -> None:
        now = self._clock.now()
        summary = self._coalescer.observe(now)
        if summary is not None:
            self._write(summary)
        if self._coalescer.keep_original():
            self._write(_redact_event(event, self._secrets))

    def flush(self) -> None:
        now = self._clock.now()
        summary = self._coalescer.flush(now)
        if summary is not None:
            self._write(summary)

    def _write(self, event: SecurityEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = _redact_event(event, self._secrets).model_dump(mode="json")
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
            handle.flush()


def _redact_event(event: SecurityEvent, secrets: tuple[str, ...]) -> SecurityEvent:
    dumped: dict[str, Any] = redact(event.model_dump(mode="json"), secrets=secrets)
    return SecurityEvent.model_validate(dumped)
