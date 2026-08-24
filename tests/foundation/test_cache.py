"""Tests for the §3 cache contract against InMemoryCache."""

from __future__ import annotations

import asyncio
import time

import pytest

from authy_package.cache import AbstractCache, InMemoryCache, RedisCache


class TestStrings:
    async def test_get_set_delete(self, cache: InMemoryCache) -> None:
        assert await cache.get("k") is None
        await cache.set("k", "v")
        assert await cache.get("k") == "v"
        assert await cache.exists("k") is True
        assert await cache.delete("k") is True
        assert await cache.delete("k") is False
        assert await cache.get("k") is None
        assert await cache.exists("k") is False

    async def test_set_requires_str(self, cache: InMemoryCache) -> None:
        with pytest.raises(ValueError):
            await cache.set("k", 123)  # type: ignore[arg-type]

    async def test_json_helpers(self, cache: InMemoryCache) -> None:
        await cache.set_json("obj", {"a": 1, "b": [1, 2]}, ttl_seconds=60)
        assert await cache.get_json("obj") == {"a": 1, "b": [1, 2]}
        assert await cache.get_json("missing") is None

    async def test_ttl_expiry_via_monotonic(self, cache: InMemoryCache) -> None:
        await cache.set("k", "v", ttl_seconds=30)
        assert 0 < await cache.ttl("k") <= 30
        # Force the deadline into the past (deterministic, no sleeping).
        cache._expiry["k"] = time.monotonic() - 1
        assert await cache.get("k") is None
        assert await cache.exists("k") is False
        assert await cache.ttl("k") == -2

    async def test_real_ttl_expires(self, cache: InMemoryCache) -> None:
        await cache.set("k", "v", ttl_seconds=1)
        await asyncio.sleep(1.05)
        assert await cache.get("k") is None

    async def test_ttl_sentinels(self, cache: InMemoryCache) -> None:
        assert await cache.ttl("missing") == -2
        await cache.set("k", "v")
        assert await cache.ttl("k") == -1


class TestCounters:
    async def test_incr_creates_at_one(self, cache: InMemoryCache) -> None:
        assert await cache.incr("c") == 1
        assert await cache.incr("c") == 2
        assert await cache.get("c") == "2"

    async def test_incr_non_integer_raises(self, cache: InMemoryCache) -> None:
        await cache.set("c", "abc")
        with pytest.raises(ValueError):
            await cache.incr("c")

    async def test_expire_missing_key(self, cache: InMemoryCache) -> None:
        assert await cache.expire("missing", 10) is False

    async def test_expire_existing_key(self, cache: InMemoryCache) -> None:
        await cache.set("k", "v")
        assert await cache.expire("k", 10) is True
        assert 0 < await cache.ttl("k") <= 10

    async def test_expired_counter_restarts(self, cache: InMemoryCache) -> None:
        await cache.incr("c")
        cache._expiry["c"] = time.monotonic() - 1
        assert await cache.incr("c") == 1


class TestLists:
    async def test_lpush_rpop_order(self, cache: InMemoryCache) -> None:
        assert await cache.lpush("l", "a") == 1
        assert await cache.lpush("l", "b", "c") == 3
        # list is [c, b, a]; rpop takes from the tail
        assert await cache.rpop("l") == "a"
        assert await cache.rpop("l") == "b"
        assert await cache.rpop("l") == "c"
        assert await cache.rpop("l") is None

    async def test_lrange_inclusive_and_negative(self, cache: InMemoryCache) -> None:
        await cache.lpush("l", "1", "2", "3", "4")  # [4, 3, 2, 1]
        assert await cache.lrange("l", 0, 1) == ["4", "3"]
        assert await cache.lrange("l", 0, -1) == ["4", "3", "2", "1"]
        assert await cache.lrange("l", -2, -1) == ["2", "1"]
        assert await cache.lrange("l", 5, 10) == []
        assert await cache.lrange("missing", 0, -1) == []

    async def test_lpush_requires_values(self, cache: InMemoryCache) -> None:
        with pytest.raises(ValueError):
            await cache.lpush("l")


class TestHashes:
    async def test_hset_hgetall_hdel(self, cache: InMemoryCache) -> None:
        await cache.hset("h", {"f1": "v1", "f2": "v2"})
        assert await cache.hgetall("h") == {"f1": "v1", "f2": "v2"}
        await cache.hset("h", {"f2": "v2b"})
        assert await cache.hgetall("h") == {"f1": "v1", "f2": "v2b"}
        assert await cache.hdel("h", "f1", "missing") == 1
        assert await cache.hgetall("h") == {"f2": "v2b"}
        assert await cache.hgetall("missing") == {}

    async def test_hset_requires_str_values(self, cache: InMemoryCache) -> None:
        with pytest.raises(ValueError):
            await cache.hset("h", {"f": 1})  # type: ignore[dict-item]


class TestTypeReplacement:
    async def test_set_replaces_list_and_hash(self, cache: InMemoryCache) -> None:
        await cache.lpush("k", "a")
        await cache.set("k", "string")
        assert await cache.get("k") == "string"
        assert await cache.lrange("k", 0, -1) == []

        await cache.hset("k2", {"f": "v"})
        await cache.set("k2", "string")
        assert await cache.hgetall("k2") == {}


class TestLifecycle:
    async def test_close_clears_state(self, cache: InMemoryCache) -> None:
        await cache.set("k", "v")
        await cache.close()
        assert await cache.get("k") is None

    async def test_health_check(self, cache: InMemoryCache) -> None:
        assert await cache.health_check() is True

    def test_is_abstract_cache(self, cache: InMemoryCache) -> None:
        assert isinstance(cache, AbstractCache)

    def test_redis_cache_is_abstract_cache(self) -> None:
        # Construction must not require a live server (§0.9).
        redis_cache = RedisCache("redis://localhost:6379")
        assert isinstance(redis_cache, AbstractCache)
