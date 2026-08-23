"""Magic-link tests: single-use race, redirect allow-list, rate limit, TTL."""

from __future__ import annotations

import asyncio

import pytest

from authy_package.errors import AuthenticationError, RateLimitError
from authy_package.passwordless.magic_link import MagicLinkManager

EMAIL = "magic@example.com"


class _EmailStub:
    def __init__(self):
        self.sent = []

    async def send_magic_link_email(self, to, magic_link, expires_in_minutes):
        self.sent.append({"to": to, "magic_link": magic_link})
        return True


@pytest.fixture
def email_stub():
    return _EmailStub()


@pytest.fixture
def magic(config, db, cache, email_stub):
    return MagicLinkManager(config, db, cache, email_service=email_stub)


async def _send(magic, db, email=EMAIL):
    await db.create_user({"email": email, "email_verified": True})
    result = await magic.send_magic_link(email)
    token = result["magic_link"].split("token=")[-1]
    return token


async def test_send_and_verify_single_use(magic, db):
    token = await _send(magic, db)
    outcome = await magic.verify_magic_link(token)
    assert outcome["user"]["email"] == EMAIL

    # Second use is rejected (missing record == consumed).
    with pytest.raises(AuthenticationError) as again:
        await magic.verify_magic_link(token)
    assert again.value.code == "magic_link_invalid"


async def test_single_use_race_exactly_one_wins(magic, db):
    token = await _send(magic, db)
    results = await asyncio.gather(
        magic.verify_magic_link(token),
        magic.verify_magic_link(token),
        magic.verify_magic_link(token),
        return_exceptions=True,
    )
    successes = [r for r in results if not isinstance(r, Exception)]
    failures = [r for r in results if isinstance(r, Exception)]
    assert len(successes) == 1
    assert len(failures) == 2
    assert all(isinstance(f, AuthenticationError) for f in failures)


async def test_expired_token_rejected(make_config, db, cache, email_stub):
    config = make_config(magic_link_ttl_seconds=1)
    magic = MagicLinkManager(config, db, cache, email_service=email_stub)
    token = await _send(magic, db)
    await asyncio.sleep(1.05)
    with pytest.raises(AuthenticationError):
        await magic.verify_magic_link(token)


async def test_open_redirect_rejected(magic, db):
    await db.create_user({"email": EMAIL})
    with pytest.raises(ValueError):
        await magic.send_magic_link(EMAIL, redirect_url="https://evil.example.net/phish")
    # Same host as base_url is allowed.
    ok = await magic.send_magic_link(EMAIL, redirect_url="http://localhost:8000/home")
    assert ok["magic_link"]


async def test_send_rate_limited(magic, db):
    await db.create_user({"email": EMAIL})
    for _ in range(3):
        await magic.send_magic_link(EMAIL)
    with pytest.raises(RateLimitError):
        await magic.send_magic_link(EMAIL)


async def test_auto_create_users(make_config, db, cache, email_stub):
    # auto_create_users=False -> no account -> user_not_found
    config = make_config(auto_create_users=False)
    magic = MagicLinkManager(config, db, cache, email_service=email_stub)
    result = await magic.send_magic_link("brand-new@example.com")
    token = result["magic_link"].split("token=")[-1]
    with pytest.raises(AuthenticationError) as exc:
        await magic.verify_magic_link(token)
    assert exc.value.code == "user_not_found"

    # auto_create_users=True -> account is created and verified
    config2 = make_config(auto_create_users=True)
    cache2 = type(cache)()
    magic2 = MagicLinkManager(config2, db, cache2, email_service=email_stub)
    result2 = await magic2.send_magic_link("created@example.com")
    token2 = result2["magic_link"].split("token=")[-1]
    outcome = await magic2.verify_magic_link(token2)
    assert outcome["user"]["email"] == "created@example.com"
    assert outcome["user"]["email_verified"] is True


async def test_unknown_token_rejected(magic, db):
    with pytest.raises(AuthenticationError):
        await magic.verify_magic_link("totally-bogus-token")
