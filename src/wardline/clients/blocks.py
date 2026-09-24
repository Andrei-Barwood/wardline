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
        """Remove all blocks for the client id. Return False when nothing active changed."""

    def unblock_incident(self, client_id: str, incident_id: str) -> bool:
        """Remove blocks for client_id associated with incident_id. Return False if none active."""

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
        self._blocks: dict[str, list[BlockInfo]] = {}

    def block(self, client_id: str, *, until: datetime, reason: str, incident_id: str) -> None:
        entry = BlockInfo(until=until, reason=reason, incident_id=incident_id)
        if client_id not in self._blocks:
            self._blocks[client_id] = []
        # Replace existing block for same incident_id if present, else append
        self._blocks[client_id] = [
            b for b in self._blocks[client_id] if b.incident_id != incident_id
        ]
        self._blocks[client_id].append(entry)

    def is_blocked(self, client_id: str, now: datetime) -> bool:
        blocks = self._blocks.get(client_id)
        if not blocks:
            return False
        return any(b.until > now for b in blocks)

    def unblock(self, client_id: str) -> bool:
        blocks = self._blocks.pop(client_id, None)
        if not blocks:
            return False
        now = datetime.now(UTC)
        return any(b.until > now for b in blocks)

    def unblock_incident(self, client_id: str, incident_id: str) -> bool:
        blocks = self._blocks.get(client_id)
        if not blocks:
            return False
        now = datetime.now(UTC)
        had_active = any(b.incident_id == incident_id and b.until > now for b in blocks)
        remaining = [b for b in blocks if b.incident_id != incident_id]
        if remaining:
            self._blocks[client_id] = remaining
        else:
            self._blocks.pop(client_id, None)
        return had_active

    def count_active(self, now: datetime) -> int:
        return sum(1 for blocks in self._blocks.values() if any(b.until > now for b in blocks))

    def list_active(self, now: datetime) -> list[str]:
        return [
            client_id
            for client_id, blocks in self._blocks.items()
            if any(b.until > now for b in blocks)
        ]
