"""Abstract async cache contract (CONTRACTS.md §3).

Async-first, generic primitives ONLY — token/session semantics live in the
consumers, which combine these primitives with the §3.1 key schema. The old
``RedisCaching`` / ``create_token_pair`` style methods are removed entirely.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

__all__ = ["AbstractCache"]


class AbstractCache(ABC):
    """Generic async cache primitives (strings, counters, lists, hashes)."""

    # -- strings -----------------------------------------------------------

    @abstractmethod
    async def get(self, key: str) -> Optional[str]:
        """Return the string value for ``key``, or ``None`` when missing/expired."""

    @abstractmethod
    async def set(self, key: str, value: str, *, ttl_seconds: Optional[int] = None) -> None:
        """Store ``value`` under ``key`` with an optional TTL in seconds."""

    async def set_json(self, key: str, obj: Any, *, ttl_seconds: Optional[int] = None) -> None:
        """Serialize ``obj`` as JSON and store it under ``key``."""
        await self.set(key, json.dumps(obj), ttl_seconds=ttl_seconds)

    async def get_json(self, key: str) -> Any:
        """Fetch ``key`` and JSON-decode it; ``None`` when missing/expired."""
        raw = await self.get(key)
        if raw is None:
            return None
        return json.loads(raw)

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete ``key``. Returns ``True`` when the key existed."""

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Return ``True`` when ``key`` exists and has not expired."""

    # -- counters / expiry --------------------------------------------------

    @abstractmethod
    async def incr(self, key: str) -> int:
        """Atomically increment an integer counter; creates it at 0 -> 1."""

    @abstractmethod
    async def expire(self, key: str, ttl_seconds: int) -> bool:
        """Set a TTL on an existing key. ``False`` when the key is missing."""

    @abstractmethod
    async def ttl(self, key: str) -> int:
        """Remaining TTL in seconds; -2 when missing, -1 when no TTL."""

    # -- lists ---------------------------------------------------------------

    @abstractmethod
    async def lpush(self, key: str, *values: str) -> int:
        """Prepend one or more values to a list; returns the new length."""

    @abstractmethod
    async def rpop(self, key: str) -> Optional[str]:
        """Remove and return the last element of a list, or ``None``."""

    @abstractmethod
    async def lrange(self, key: str, start: int, stop: int) -> List[str]:
        """Return list elements from ``start`` to ``stop`` inclusive."""

    # -- hashes --------------------------------------------------------------

    @abstractmethod
    async def hset(self, key: str, mapping: Dict[str, str]) -> None:
        """Set hash fields from ``mapping``."""

    @abstractmethod
    async def hgetall(self, key: str) -> Dict[str, str]:
        """Return all fields/values of a hash (empty dict when missing)."""

    @abstractmethod
    async def hdel(self, key: str, *fields: str) -> int:
        """Delete hash ``fields``; returns the number of fields removed."""

    # -- lifecycle ------------------------------------------------------------

    @abstractmethod
    async def close(self) -> None:
        """Release underlying resources."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Return ``True`` when the backend is reachable."""
