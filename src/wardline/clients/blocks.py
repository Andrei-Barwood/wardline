"""Logical client blocks.

Blocks are in-memory and process-scoped; restarting the process clears them.
Blocks apply strictly to client_id, never to the API key, ensuring administrative
access can be regained if an admin client_id is blocked (using another client_id with
the same admin key, or restarting the process). Do not block by key.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol


@dataclass(frozen=True)
class BlockInfo:
    until: datetime
    reason: str
    incident_id: str


class BlockRegistry(Protocol):
    """Protocol for managing logical client blocks."""

    def block(self, client_id: str, *, until: datetime, reason: str, incident_id: str) -> None:
        """Record a logical block for a synthetic client id."""

    def is_blocked(self, client_id: str, now: datetime) -> bool:
        """Return whether the client id is blocked at the given instant."""

    def unblock(self, client_id: str) -> bool:
        """Remove blocks for the client id. Return False when nothing changed."""

    def count_active(self, now: datetime) -> int:
        """Return the number of active blocks at the given instant."""

    def list_active(self, now: datetime) -> list[str]:
        """Return a list of blocked client ids active at the given instant."""


class InMemoryBlockRegistry:
    """In-memory logical client block registry.

    Blocks are in-memory and process-scoped; restarting the process clears them.
    Blocks apply strictly to client_id, never to the API key, ensuring administrative
    access can be regained if an admin client_id is blocked.
    """

    def __init__(self) -> None:
        self._blocks: dict[str, BlockInfo] = {}

    def block(self, client_id: str, *, until: datetime, reason: str, incident_id: str) -> None:
        self._blocks[client_id] = BlockInfo(until=until, reason=reason, incident_id=incident_id)

    def is_blocked(self, client_id: str, now: datetime) -> bool:
        info = self._blocks.get(client_id)
        if info is None:
            return False
        if now >= info.until:
            return False
        return True

    def unblock(self, client_id: str) -> bool:
        info = self._blocks.pop(client_id, None)
        if info is None:
            return False
        # If the block was already expired, nothing active changed
        now = datetime.now(UTC)
        if now >= info.until:
            return False
        return True

    def count_active(self, now: datetime) -> int:
        return sum(1 for info in self._blocks.values() if info.until > now)

    def list_active(self, now: datetime) -> list[str]:
        return [client_id for client_id, info in self._blocks.items() if info.until > now]
