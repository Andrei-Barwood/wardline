"""Logical client blocks. This first registry never blocks anyone."""

from datetime import datetime
from typing import Protocol


class BlockRegistry(Protocol):
    def block(self, client_id: str, *, until: datetime, reason: str, incident_id: str) -> None:
        """Record a logical block for a synthetic client id."""

    def is_blocked(self, client_id: str, now: datetime) -> bool:
        """Return whether the client id is blocked at the given instant."""

    def unblock(self, client_id: str) -> bool:
        """Remove blocks for the client id. Return False when nothing changed."""

    def count_active(self, now: datetime) -> int:
        """Return the number of active blocks at the given time."""


class InMemoryBlockRegistry:
    """Stand-in that keeps the process open. Later prompts store real blocks."""

    def block(self, client_id: str, *, until: datetime, reason: str, incident_id: str) -> None:
        del client_id, until, reason, incident_id

    def is_blocked(self, client_id: str, now: datetime) -> bool:
        del client_id, now
        return False

    def unblock(self, client_id: str) -> bool:
        del client_id
        return False

    def count_active(self, now: datetime) -> int:
        del now
        return 0
