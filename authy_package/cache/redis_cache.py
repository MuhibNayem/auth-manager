"""Redis cache implementation on ``redis.asyncio`` (CONTRACTS.md §3).

Replaces the legacy ``aioredis``-based ``RedisCaching`` class with the exact
:class:`~authy_package.cache.abstract_cache.AbstractCache` primitive surface.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from authy_package.cache.abstract_cache import AbstractCache

logger = logging.getLogger("authy.cache.redis")

__all__ = ["RedisCache"]


class RedisCache(AbstractCache):
    """Redis-backed async cache using ``redis.asyncio`` (NOT aioredis)."""

    def __init__(
        self,
        url: str = "redis://localhost:6379",
        *,
        client: Optional[Any] = None,
    ) -> None:
        """Create the cache.

        Args:
            url: Redis connection URL (used when ``client`` is not given).
            client: Optional pre-built ``redis.asyncio.Redis`` client; the
                caller retains ownership of its lifecycle in that case.

        Raises:
            ImportError: When the ``redis`` package is unavailable (§0.9).
        """
        if client is None:
            try:
                from redis import asyncio as redis_asyncio
            except ImportError as exc:
                raise ImportError(
                    "RedisCache requires the 'redis' package (redis.asyncio)"
                ) from exc
            self._client = redis_asyncio.from_url(url, decode_responses=True)
            self._owns_client = True
        else:
            self._client = client
            self._owns_client = False

    @property
    def client(self) -> Any:
        """The underlying ``redis.asyncio.Redis`` client."""
        return self._client

    # -- strings -----------------------------------------------------------

    async def get(self, key: str) -> Optional[str]:
        return await self._client.get(key)

    async def set(self, key: str, value: str, *, ttl_seconds: Optional[int] = None) -> None:
        if not isinstance(value, str):
            raise ValueError(f"value must be a str, got {type(value).__name__}")
        if ttl_seconds is None:
            await self._client.set(key, value)
        else:
            if ttl_seconds <= 0:
                raise ValueError("ttl_seconds must be positive")
            await self._client.set(key, value, ex=ttl_seconds)

    async def delete(self, key: str) -> bool:
        return bool(await self._client.delete(key))

    async def exists(self, key: str) -> bool:
        return bool(await self._client.exists(key))

    # -- counters / expiry ----------------------------------------------------

    async def incr(self, key: str) -> int:
        return int(await self._client.incr(key))

    async def expire(self, key: str, ttl_seconds: int) -> bool:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        return bool(await self._client.expire(key, ttl_seconds))

    async def ttl(self, key: str) -> int:
        # Redis natively returns -2 for missing keys and -1 for no TTL.
        return int(await self._client.ttl(key))

    # -- lists -----------------------------------------------------------------

    async def lpush(self, key: str, *values: str) -> int:
        if not values:
            raise ValueError("lpush requires at least one value")
        return int(await self._client.lpush(key, *values))

    async def rpop(self, key: str) -> Optional[str]:
        return await self._client.rpop(key)

    async def lrange(self, key: str, start: int, stop: int) -> List[str]:
        return list(await self._client.lrange(key, start, stop))

    # -- hashes -----------------------------------------------------------------

    async def hset(self, key: str, mapping: Dict[str, str]) -> None:
        if not isinstance(mapping, dict):
            raise ValueError("mapping must be a dict")
        if mapping:
            await self._client.hset(key, mapping=mapping)

    async def hgetall(self, key: str) -> Dict[str, str]:
        return dict(await self._client.hgetall(key))

    async def hdel(self, key: str, *fields: str) -> int:
        if not fields:
            return 0
        return int(await self._client.hdel(key, *fields))

    # -- lifecycle ---------------------------------------------------------------

    async def close(self) -> None:
        if not self._owns_client:
            return
        close = getattr(self._client, "aclose", None) or getattr(self._client, "close")
        result = close()
        if result is not None:
            await result

    async def health_check(self) -> bool:
        try:
            return bool(await self._client.ping())
        except Exception as exc:  # noqa: BLE001 - health check must not raise
            logger.warning("Redis health check failed: %s", exc)
            return False
