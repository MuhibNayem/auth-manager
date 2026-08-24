"""Bot protection tests: sliding windows, heuristics, provider quirks."""

from __future__ import annotations

import inspect
import time

import pytest

from authy_package.bot_protection import (
    BotProtectionError,
    BotProtectionManager,
    RateLimitExceededError,
    RiskLevel,
)
from authy_package.bot_protection.abstract_provider import (
    AbstractCaptchaProvider,
    CaptchaVerificationResult,
)
from authy_package.cache import InMemoryCache


class FakeCaptchaProvider(AbstractCaptchaProvider):
    """Returns a configurable verification result without network."""

    def __init__(self, success: bool = True, risk_score: float = 0.0) -> None:
        self.success = success
        self.risk_score = risk_score

    async def verify_token(self, token, remote_ip=None):
        return CaptchaVerificationResult(
            success=self.success,
            is_human=self.success,
            risk_score=self.risk_score,
            risk_level=RiskLevel.LOW if self.success else RiskLevel.HIGH,
        )

    @property
    def provider_name(self) -> str:
        return "fake-captcha"

    @property
    def site_key(self) -> str:
        return "site-key"


@pytest.fixture
def cache() -> InMemoryCache:
    return InMemoryCache()


# ---------------------------------------------------------------------------
# sliding window counting
# ---------------------------------------------------------------------------

async def test_minute_window_counts_and_raises(cache):
    manager = BotProtectionManager(
        FakeCaptchaProvider(), cache, max_requests_per_minute=3, max_requests_per_hour=100
    )
    for _ in range(3):
        assert await manager.check_rate_limit("login:u@example.com") is True

    with pytest.raises(RateLimitExceededError) as excinfo:
        await manager.check_rate_limit("login:u@example.com")
    assert excinfo.value.retry_after == 60


async def test_hour_window_counts(cache):
    manager = BotProtectionManager(
        FakeCaptchaProvider(), cache, max_requests_per_minute=100, max_requests_per_hour=2
    )
    await manager.check_rate_limit("id")
    await manager.check_rate_limit("id")
    with pytest.raises(RateLimitExceededError) as excinfo:
        await manager.check_rate_limit("id")
    assert excinfo.value.retry_after == 3600


async def test_window_trims_expired_timestamps(cache):
    manager = BotProtectionManager(
        FakeCaptchaProvider(), cache, max_requests_per_minute=2, max_requests_per_hour=100
    )
    minute_key = manager._rate_limit_key("id", "minute")

    # Seed two OLD timestamps (outside the 60s window).
    old = str(time.time() - 120)
    await cache.lpush(minute_key, old, old)

    # The trimming pass must ignore them: two fresh requests pass.
    assert await manager.check_rate_limit("id") is True
    assert await manager.check_rate_limit("id") is True
    with pytest.raises(RateLimitExceededError):
        await manager.check_rate_limit("id")

    # Old entries were trimmed out of the stored list.
    stored = await cache.lrange(minute_key, 0, -1)
    assert all(float(ts) > time.time() - 60 for ts in stored)


async def test_rate_limit_disabled(cache):
    manager = BotProtectionManager(
        FakeCaptchaProvider(), cache, enable_rate_limiting=False, max_requests_per_minute=1
    )
    for _ in range(5):
        assert await manager.check_rate_limit("id") is True


# ---------------------------------------------------------------------------
# behavioral heuristics + coherent scoring
# ---------------------------------------------------------------------------

def test_user_agent_heuristics(cache):
    manager = BotProtectionManager(FakeCaptchaProvider(), cache)

    missing = manager.analyze_user_agent(None)
    assert missing.is_suspicious and "missing_user_agent" in missing.flags

    bot = manager.analyze_user_agent("python-requests/2.31")
    assert any(flag.startswith("bot_pattern:") for flag in bot.flags)

    clean = manager.analyze_user_agent(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
    )
    assert not clean.is_suspicious


def test_ip_heuristic_is_honest_and_local(cache):
    manager = BotProtectionManager(FakeCaptchaProvider(), cache)

    metadata = manager.analyze_ip_address("169.254.169.254")
    assert "cloud_metadata_ip" in metadata.flags
    assert metadata.risk_score >= 0.8

    loopback = manager.analyze_ip_address("127.0.0.1")
    assert "loopback_ip" in loopback.flags

    bogus = manager.analyze_ip_address("not-an-ip")
    assert "unparseable_ip" in bogus.flags

    public = manager.analyze_ip_address("93.184.216.34")
    assert not public.is_suspicious
    assert public.risk_score == 0.0

    missing = manager.analyze_ip_address(None)
    assert "missing_ip" in missing.flags


async def test_verify_captcha_behavioral_risk_only_raises(cache):
    manager = BotProtectionManager(FakeCaptchaProvider(), cache)

    result = await manager.verify_captcha(
        "token", ip_address="169.254.169.254", user_agent="curl/8.0"
    )
    # Behavioral flags attached and score strictly above the clean baseline.
    assert result.flags
    assert result.risk_score > 0.0

    clean = await manager.verify_captcha(
        "token", ip_address="93.184.216.34",
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120",
    )
    assert clean.risk_score == 0.0
    assert clean.is_human is True


async def test_verify_captcha_without_provider_raises(cache):
    manager = BotProtectionManager(None, cache)
    with pytest.raises(BotProtectionError):
        await manager.verify_captcha("token")


def test_risk_level_thresholds(cache):
    manager = BotProtectionManager(
        FakeCaptchaProvider(), cache, risk_threshold_medium=0.5, risk_threshold_high=0.8
    )
    assert manager._calculate_risk_level(0.1) is RiskLevel.LOW
    assert manager._calculate_risk_level(0.5) is RiskLevel.MEDIUM
    assert manager._calculate_risk_level(0.8) is RiskLevel.HIGH


async def test_should_require_captcha(cache):
    manager = BotProtectionManager(FakeCaptchaProvider(), cache)
    assert await manager.should_require_captcha("login") is True
    assert await manager.should_require_captcha("view_page") is False
    assert await manager.should_require_captcha("view_page", risk_score=0.9) is True


# ---------------------------------------------------------------------------
# captcha provider client quirk regression
# ---------------------------------------------------------------------------

def test_hcaptcha_client_is_async_method_not_property():
    from authy_package.bot_protection.hcaptcha_provider import hCaptchaProvider

    assert inspect.iscoroutinefunction(hCaptchaProvider.get_client)
    # No lingering async-property footgun.
    assert not isinstance(
        inspect.getattr_static(hCaptchaProvider, "client", None), property
    ) or not inspect.iscoroutinefunction(
        inspect.getattr_static(hCaptchaProvider, "client").fget
    )


def test_recaptcha_client_is_async_method_not_property():
    from authy_package.bot_protection.recaptcha_provider import ReCaptchaProvider

    assert inspect.iscoroutinefunction(ReCaptchaProvider.get_client)


async def test_hcaptcha_get_client_caches():
    from authy_package.bot_protection.hcaptcha_provider import hCaptchaProvider

    provider = hCaptchaProvider(secret_key="s", site_key="k")
    try:
        client1 = await provider.get_client()
        client2 = await provider.get_client()
        assert client1 is client2
    finally:
        await provider.close()


def test_hcaptcha_docstring_env_vars_spelled_correctly():
    from authy_package.bot_protection import hcaptcha_provider

    assert "HCATCHA" not in (hcaptcha_provider.__doc__ or "")
