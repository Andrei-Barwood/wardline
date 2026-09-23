"""Audit log protocol. The null sink discards events until file logging exists."""

from typing import Protocol

from wardline.contracts import SecurityEvent


class AuditLog(Protocol):
    def append(self, event: SecurityEvent) -> None:
        """Record one security event."""


class NullAuditLog:
    """Discard audit events. Prompt 06 replaces this with a JSONL file."""

    def append(self, event: SecurityEvent) -> None:
        del event
