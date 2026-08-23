"""SMS manager tests: secure lifecycle, caps, expiry, fixed-window limits."""

from __future__ import annotations

import inspect
import re
import time

import pytest

from authy_package.cache import InMemoryCache
from authy_package.sms import (
    InvalidVerificationCodeError,
    SMSManager,
    SMSProviderError,
    TooManyAttemptsError,
    VerificationCodeExpiredError,
)
from authy_package.sms.abstract_provider import (
    AbstractSMSProvider,
    SMSResponse,
)

PHONE = "+15551230001"


class FakeProvider(AbstractSMSProvider):
    """Captures messages so tests can recover the issued code."""

    provider_name = "fake"

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []
        self.fail_with: Exception | None = None

    async def send_sms(self, to, body, from_number=None):
        if self.fail_with is not None:
            raise self.fail_with
        self.sent.append((to, body))
        return SMSResponse(success=True, message_id=f"msg-{len(self.sent)}", status="sent")

    async def check_delivery_status(self, message_id):
        return "delivered"

    @property
    def last_code(self) -> str:
        match = re.search(r"code is: (\d+)", self.sent[-1][1])
        assert match, f"no code found in message body: {self.sent[-1][1]!r}"
        return match.group(1)


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture
def cache() -> InMemoryCache:
    return InMemoryCache()


def make_manager(provider, cache, **overrides) -> SMSManager:
    defaults = dict(
        code_length=6,
        expiration_seconds=300,
        max_attempts=3,
        rate_limit_window_seconds=60,
        max_sends_per_window=3,
    )
    defaults.update(overrides)
    return SMSManager(provider, cache, **defaults)


# ---------------------------------------------------------------------------
# code generation security
# ---------------------------------------------------------------------------

def test_code_generation_uses_secrets_module():
    """Regression: codes must come from the CSPRNG-backed secrets module."""
    source = inspect.getsource(SMSManager._generate_code)
    assert "secrets.choice" in source
    assert "random." not in source


async def test_generated_code_shape(provider, cache):
    manager = make_manager(provider, cache, code_length=8)
    code = manager._generate_code()
    assert len(code) == 8
    assert code.isdigit()


# ---------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------

async def test_send_and_verify_ok(provider, cache):
    manager = make_manager(provider, cache)
    result = await manager.send_verification_code(PHONE)
    assert result["success"] is True
    assert result["provider"] == "fake"
    assert result["expires_in"] == 300

    code = provider.last_code
    verified = await manager.verify_code(PHONE, code)
    assert verified == {"success": True, "verified": True, "phone": PHONE}

    # Codes are single-use: verifying again must fail as expired/absent.
    with pytest.raises(VerificationCodeExpiredError):
        await manager.verify_code(PHONE, code)


async def test_state_stored_hashed_under_contract_key(provider, cache):
    """§3.1: authy:sms:{phone} json with code_hash/attempts/expires_at."""
    manager = make_manager(provider, cache)
    await manager.send_verification_code(PHONE)

    record = await cache.get_json(f"authy:sms:{PHONE}")
    assert record is not None
    assert set(record) >= {"code_hash", "attempts", "expires_at", "last_sent_at"}
    # The plaintext code must never be persisted.
    assert provider.last_code not in str(record)

    # Constant-time path: wrong code raises, attempts increment.
    wrong = "0" * 6 if provider.last_code != "0" * 6 else "1" * 6
    with pytest.raises(InvalidVerificationCodeError):
        await manager.verify_code(PHONE, wrong)
    record = await cache.get_json(f"authy:sms:{PHONE}")
    assert record["attempts"] == 1


async def test_wrong_code_until_attempts_cap(provider, cache):
    manager = make_manager(provider, cache, max_attempts=3)
    await manager.send_verification_code(PHONE)
    code = provider.last_code
    wrong = "0" * 6 if code != "0" * 6 else "1" * 6

    for _ in range(2):
        with pytest.raises(InvalidVerificationCodeError):
            await manager.verify_code(PHONE, wrong)

    # Third wrong attempt exhausts the cap.
    with pytest.raises(TooManyAttemptsError):
        await manager.verify_code(PHONE, wrong)

    # State is deleted after exhaustion — even the right code is rejected.
    with pytest.raises(VerificationCodeExpiredError):
        await manager.verify_code(PHONE, code)


async def test_code_expiry_from_config(provider, cache):
    manager = make_manager(provider, cache, expiration_seconds=300)
    await manager.send_verification_code(PHONE)

    # Force the record past its expiry without sleeping.
    key = f"authy:sms:{PHONE}"
    record = await cache.get_json(key)
    record["expires_at"] = time.time() - 1
    await cache.set_json(key, record, ttl_seconds=300)

    with pytest.raises(VerificationCodeExpiredError):
        await manager.verify_code(PHONE, provider.last_code)
    assert await cache.get(key) is None  # expired record deleted


async def test_expiry_naturally_via_ttl(provider, cache):
    manager = make_manager(provider, cache, expiration_seconds=1)
    await manager.send_verification_code(PHONE)
    import asyncio

    await asyncio.sleep(1.15)
    with pytest.raises(VerificationCodeExpiredError):
        await manager.verify_code(PHONE, provider.last_code)


# ---------------------------------------------------------------------------
# fixed-window rate limiting (no sliding reset)
# ---------------------------------------------------------------------------

async def test_send_rate_limit_window_is_fixed(provider, cache):
    manager = make_manager(provider, cache, max_sends_per_window=2)

    await manager.send_verification_code(PHONE)
    counter_key = f"authy:ratelimit:sms:{PHONE}"
    ttl_after_first = await cache.ttl(counter_key)
    assert 0 < ttl_after_first <= 60

    await manager.send_verification_code(PHONE)
    ttl_after_second = await cache.ttl(counter_key)
    # TTL must NOT be refreshed on subsequent sends (the old sliding bug).
    assert ttl_after_second <= ttl_after_first

    with pytest.raises(TooManyAttemptsError) as excinfo:
        await manager.send_verification_code(PHONE)
    assert excinfo.value.retry_after >= 1
    # Only two messages were actually delivered.
    assert len(provider.sent) == 2


async def test_rate_limit_window_reopens(provider, cache):
    manager = make_manager(provider, cache, max_sends_per_window=1,
                           rate_limit_window_seconds=60)
    await manager.send_verification_code(PHONE)
    with pytest.raises(TooManyAttemptsError):
        await manager.send_verification_code(PHONE)

    # Simulate window expiry by deleting the counter (TTL-driven in prod).
    await cache.delete(f"authy:ratelimit:sms:{PHONE}")
    result = await manager.send_verification_code(PHONE)
    assert result["success"] is True


# ---------------------------------------------------------------------------
# provider failure + delivery passthrough
# ---------------------------------------------------------------------------

async def test_provider_failure_passthrough(provider, cache):
    manager = make_manager(provider, cache)
    provider.fail_with = SMSProviderError("upstream 503")

    result = await manager.send_verification_code(PHONE)
    assert result["success"] is False
    assert "upstream 503" in result["error"]
    # No verification state may exist after a failed send.
    assert await cache.get(f"authy:sms:{PHONE}") is None


async def test_delivery_status_passthrough(provider, cache):
    manager = make_manager(provider, cache)
    result = await manager.send_verification_code(PHONE)
    status = await manager.get_delivery_status(result["message_id"])
    assert status == "delivered"


async def test_resend_invalidates_previous_code(provider, cache):
    manager = make_manager(provider, cache)
    await manager.send_verification_code(PHONE)
    old_code = provider.last_code

    await manager.resend_code(PHONE)
    new_code = provider.last_code

    if old_code != new_code:
        with pytest.raises(InvalidVerificationCodeError):
            await manager.verify_code(PHONE, old_code)
        # The failed attempt consumed one try; re-send keeps the test simple:
    verified = await manager.verify_code(PHONE, new_code)
    assert verified["verified"] is True
