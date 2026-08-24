"""Tests for §6/§3.1 login rate-limit and lockout helpers."""

from __future__ import annotations

import pytest

from tessera.errors import AuthenticationError, RateLimitError
from tessera.utils.security import (
    LOCKOUT_KEY_TEMPLATE,
    LOGIN_RATE_LIMIT_KEY_TEMPLATE,
    clear_login_failures,
    enforce_login_rate_limit,
    record_login_failure,
)

IDENTIFIER = "alice@example.test"


@pytest.fixture
def rl_config(config):
    config.rate_limit_max_attempts = 3
    config.rate_limit_window_seconds = 300
    config.account_lockout_duration_seconds = 900
    return config


class TestEnforce:
    async def test_allows_attempts_under_budget(self, cache, rl_config) -> None:
        for _ in range(3):
            await enforce_login_rate_limit(cache, IDENTIFIER, config=rl_config)

    async def test_rate_limit_error_when_budget_exhausted(self, cache, rl_config) -> None:
        counter_key = LOGIN_RATE_LIMIT_KEY_TEMPLATE.format(identifier=IDENTIFIER)
        await cache.set(counter_key, str(rl_config.rate_limit_max_attempts))
        await cache.expire(counter_key, 120)
        with pytest.raises(RateLimitError) as excinfo:
            await enforce_login_rate_limit(cache, IDENTIFIER, config=rl_config)
        assert 1 <= excinfo.value.retry_after <= 120

    async def test_lockout_raises_authentication_error(self, cache, rl_config) -> None:
        lockout_key = LOCKOUT_KEY_TEMPLATE.format(identifier=IDENTIFIER)
        await cache.set(lockout_key, "1", ttl_seconds=900)
        with pytest.raises(AuthenticationError) as excinfo:
            await enforce_login_rate_limit(cache, IDENTIFIER, config=rl_config)
        assert excinfo.value.code == "account_locked"

    async def test_disabled_rate_limiting_is_a_no_op(self, cache, rl_config) -> None:
        rl_config.rate_limit_enabled = False
        counter_key = LOGIN_RATE_LIMIT_KEY_TEMPLATE.format(identifier=IDENTIFIER)
        await cache.set(counter_key, "999")
        await enforce_login_rate_limit(cache, IDENTIFIER, config=rl_config)

    async def test_empty_identifier_rejected(self, cache, rl_config) -> None:
        with pytest.raises(ValueError):
            await enforce_login_rate_limit(cache, "", config=rl_config)


class TestRecordFailure:
    async def test_counter_increments_and_window_set(self, cache, rl_config) -> None:
        counter_key = LOGIN_RATE_LIMIT_KEY_TEMPLATE.format(identifier=IDENTIFIER)
        await record_login_failure(cache, IDENTIFIER, config=rl_config)
        assert await cache.get(counter_key) == "1"
        assert 0 < await cache.ttl(counter_key) <= 300

    async def test_lockout_engages_at_threshold(self, cache, rl_config) -> None:
        lockout_key = LOCKOUT_KEY_TEMPLATE.format(identifier=IDENTIFIER)
        counter_key = LOGIN_RATE_LIMIT_KEY_TEMPLATE.format(identifier=IDENTIFIER)
        for _ in range(rl_config.rate_limit_max_attempts):
            await record_login_failure(cache, IDENTIFIER, config=rl_config)
        assert await cache.exists(lockout_key) is True
        assert 0 < await cache.ttl(lockout_key) <= 900
        # Counter is cleared: lockout supersedes rate limiting.
        assert await cache.exists(counter_key) is False

    async def test_full_lockout_flow(self, cache, rl_config) -> None:
        for i in range(rl_config.rate_limit_max_attempts):
            await enforce_login_rate_limit(cache, IDENTIFIER, config=rl_config)
            await record_login_failure(cache, IDENTIFIER, config=rl_config)
        with pytest.raises(AuthenticationError):
            await enforce_login_rate_limit(cache, IDENTIFIER, config=rl_config)

    async def test_disabled_is_a_no_op(self, cache, rl_config) -> None:
        rl_config.rate_limit_enabled = False
        await record_login_failure(cache, IDENTIFIER, config=rl_config)
        counter_key = LOGIN_RATE_LIMIT_KEY_TEMPLATE.format(identifier=IDENTIFIER)
        assert await cache.exists(counter_key) is False


class TestClear:
    async def test_clear_removes_counter_and_lockout(self, cache, rl_config) -> None:
        for _ in range(rl_config.rate_limit_max_attempts):
            await record_login_failure(cache, IDENTIFIER, config=rl_config)
        lockout_key = LOCKOUT_KEY_TEMPLATE.format(identifier=IDENTIFIER)
        assert await cache.exists(lockout_key) is True
        await clear_login_failures(cache, IDENTIFIER, config=rl_config)
        counter_key = LOGIN_RATE_LIMIT_KEY_TEMPLATE.format(identifier=IDENTIFIER)
        assert await cache.exists(counter_key) is False
        assert await cache.exists(lockout_key) is False
        await enforce_login_rate_limit(cache, IDENTIFIER, config=rl_config)
