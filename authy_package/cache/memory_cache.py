"""In-memory cache implementation (CONTRACTS.md §3).

Single-process implementation with monotonic-clock TTL expiry, lists and
hashes. Used by tests and development; implements exactly the
:class:`~authy_package.cache.abstract_cache.AbstractCache` primitives.
"""

from __future__ import annotations

import logging
import math
import time
from typing import Dict, List, Optional

from authy_package.cache.abstract_cache import AbstractCache

logger = logging.getLogger("authy.cache.memory")

__all__ = ["InMemoryCache"]


def _require_str(name: str, value: object) -> str:
    """Validate that a cache value is a string (matches Redis semantics)."""
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a str, got {type(value).__name__}")
    return value


class InMemoryCache(AbstractCache):
    """Dict-backed async cache with TTL expiry, lists and hashes."""

    def __init__(self) -> None:
        self._values: Dict[str, str] = {}
        self._lists: Dict[str, List[str]] = {}
        self._hashes: Dict[str, Dict[str, str]] = {}
        #: key -> monotonic deadline (applies to any key type).
        self._expiry: Dict[str, float] = {}

    # -- internal helpers ---------------------------------------------------

    def _purge_if_expired(self, key: str) -> None:
        deadline = self._expiry.get(key)
        if deadline is not None and time.monotonic() >= deadline:
            self._values.pop(key, None)
            self._lists.pop(key, None)
            self._hashes.pop(key, None)
            self._expiry.pop(key, None)

    def _exists_any(self, key: str) -> bool:
        return key in self._values or key in self._lists or key in self._hashes

    def _remove_key(self, key: str) -> bool:
        existed = self._exists_any(key)
        self._values.pop(key, None)
        self._lists.pop(key, None)
        self._hashes.pop(key, None)
        self._expiry.pop(key, None)
        return existed

    def _set_expiry(self, key: str, ttl_seconds: Optional[int]) -> None:
        if ttl_seconds is None:
            self._expiry.pop(key, None)
        else:
            if ttl_seconds <= 0:
                raise ValueError("ttl_seconds must be positive")
            self._expiry[key] = time.monotonic() + ttl_seconds

    # -- strings -------------------------------------------------------------

    async def get(self, key: str) -> Optional[str]:
        self._purge_if_expired(key)
        return self._values.get(key)

    async def set(self, key: str, value: str, *, ttl_seconds: Optional[int] = None) -> None:
        _require_str("value", value)
        self._purge_if_expired(key)
        # Redis SET replaces the key regardless of its previous type.
        self._lists.pop(key, None)
        self._hashes.pop(key, None)
        self._values[key] = value
        self._set_expiry(key, ttl_seconds)

    async def delete(self, key: str) -> bool:
        self._purge_if_expired(key)
        return self._remove_key(key)

    async def exists(self, key: str) -> bool:
        self._purge_if_expired(key)
        return self._exists_any(key)

    # -- counters / expiry ----------------------------------------------------

    async def incr(self, key: str) -> int:
        self._purge_if_expired(key)
        raw = self._values.get(key)
        if raw is None:
            new_value = 1
        else:
            try:
                new_value = int(raw) + 1
            except ValueError as exc:
                raise ValueError(f"Value at {key!r} is not an integer") from exc
        self._values[key] = str(new_value)
        return new_value

    async def expire(self, key: str, ttl_seconds: int) -> bool:
        self._purge_if_expired(key)
        if not self._exists_any(key):
            return False
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._expiry[key] = time.monotonic() + ttl_seconds
        return True

    async def ttl(self, key: str) -> int:
        self._purge_if_expired(key)
        if not self._exists_any(key):
            return -2
        deadline = self._expiry.get(key)
        if deadline is None:
            return -1
        return max(0, math.ceil(deadline - time.monotonic()))

    # -- lists -----------------------------------------------------------------

    async def lpush(self, key: str, *values: str) -> int:
        if not values:
            raise ValueError("lpush requires at least one value")
        for value in values:
            _require_str("value", value)
        self._purge_if_expired(key)
        # Redis LPUSH replaces a non-list key.
        self._values.pop(key, None)
        self._hashes.pop(key, None)
        lst = self._lists.setdefault(key, [])
        for value in values:
            lst.insert(0, value)
        return len(lst)

    async def rpop(self, key: str) -> Optional[str]:
        self._purge_if_expired(key)
        lst = self._lists.get(key)
        if not lst:
            return None
        value = lst.pop()
        if not lst:
            self._remove_key(key)
        return value

    async def lrange(self, key: str, start: int, stop: int) -> List[str]:
        self._purge_if_expired(key)
        lst = self._lists.get(key, [])
        length = len(lst)
        if length == 0:
            return []
        # Redis semantics: inclusive bounds, negative indexes from the end.
        if start < 0:
            start = max(0, length + start)
        if stop < 0:
            stop = length + stop
        if start > stop or start >= length:
            return []
        return list(lst[start : stop + 1])

    # -- hashes -----------------------------------------------------------------

    async def hset(self, key: str, mapping: Dict[str, str]) -> None:
        if not isinstance(mapping, dict):
            raise ValueError("mapping must be a dict")
        for field, value in mapping.items():
            _require_str("hash field", field)
            _require_str("hash value", value)
        self._purge_if_expired(key)
        # Redis HSET replaces a non-hash key.
        self._values.pop(key, None)
        self._lists.pop(key, None)
        self._hashes.setdefault(key, {}).update(mapping)

    async def hgetall(self, key: str) -> Dict[str, str]:
        self._purge_if_expired(key)
        return dict(self._hashes.get(key, {}))

    async def hdel(self, key: str, *fields: str) -> int:
        self._purge_if_expired(key)
        entry = self._hashes.get(key)
        if not entry:
            return 0
        removed = 0
        for field in fields:
            if field in entry:
                del entry[field]
                removed += 1
        if not entry:
            self._remove_key(key)
        return removed

    # -- lifecycle ---------------------------------------------------------------

    async def close(self) -> None:
        self._values.clear()
        self._lists.clear()
        self._hashes.clear()
        self._expiry.clear()

    async def health_check(self) -> bool:
        return True
