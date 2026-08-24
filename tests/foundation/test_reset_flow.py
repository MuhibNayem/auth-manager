"""Tests for the §6 password-reset flow (SecurityManager)."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

import pytest

from authy_package.errors import AuthenticationError
from authy_package.utils import security
from authy_package.utils.security import (
    RESET_TOKEN_CACHE_PREFIX,
    SecurityManager,
    generate_reset_token,
    hash_password,
    verify_password,
)


@pytest.fixture
async def user(db) -> Dict[str, Any]:
    return await db.create_user(
        {
            "username": "alice",
            "email": "Alice@Example.test",
            "hashed_password": hash_password("Original-Pass-1", bcrypt_rounds=4),
        }
    )


@pytest.fixture
def captured_emails(security_manager: SecurityManager) -> List[Dict[str, Any]]:
    """Capture outbound emails instead of no-op'ing them."""
    sent: List[Dict[str, Any]] = []

    async def fake_send(*, to_email: str, subject: str, text_body: str, html_body: str):
        sent.append(
            {
                "to_email": to_email,
                "subject": subject,
                "text_body": text_body,
                "html_body": html_body,
            }
        )
        return {"sent": True, "provider": "fake"}

    security_manager._email.send = fake_send  # type: ignore[method-assign]
    return sent


@pytest.fixture
def token_capture(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    """Observe generated reset tokens without changing their randomness."""
    seen: List[str] = []
    original = security.generate_reset_token

    def wrapper() -> str:
        token = original()
        seen.append(token)
        return token

    monkeypatch.setattr(security, "generate_reset_token", wrapper)
    return seen


class TestResetRequest:
    async def test_request_stores_hashed_token_only(
        self,
        security_manager: SecurityManager,
        cache,
        user: Dict[str, Any],
        token_capture: List[str],
        captured_emails: List[Dict[str, Any]],
    ) -> None:
        result = await security_manager.request_password_reset(email="alice@example.test")
        assert "reset" in result["message"].lower()
        assert len(token_capture) == 1
        token = token_capture[0]

        token_hash = hashlib.sha256(token.encode()).hexdigest()
        key = RESET_TOKEN_CACHE_PREFIX + token_hash
        raw = await cache.get(key)
        assert raw is not None, "token must be stored under authy:reset:{sha256(token)}"
        record = json.loads(raw)
        assert record["user_id"] == user["id"]
        assert record["token_hash"] == token_hash

        # The plaintext token must never appear at rest.
        for value in cache._values.values():
            assert token not in value

    async def test_email_contains_link_but_no_bare_token(
        self,
        security_manager: SecurityManager,
        user: Dict[str, Any],
        token_capture: List[str],
        captured_emails: List[Dict[str, Any]],
        config,
    ) -> None:
        await security_manager.request_password_reset(email="alice@example.test")
        token = token_capture[0]
        assert len(captured_emails) == 1
        email = captured_emails[0]
        expected_link = (
            f"{config.base_url.rstrip('/')}/auth/reset-password?token={token}"
        )
        assert expected_link in email["text_body"]
        assert expected_link in email["html_body"]
        # Token appears only inside the link, never as standalone text.
        assert email["text_body"].count(token) == 1
        assert email["html_body"].count(token) == 1
        assert "here is the reset token" not in email["html_body"].lower()

    async def test_unknown_user_gets_identical_response(
        self, security_manager: SecurityManager, cache, token_capture: List[str]
    ) -> None:
        result = await security_manager.request_password_reset(email="ghost@example.test")
        assert "reset" in result["message"].lower()
        assert token_capture == []  # no token issued for unknown accounts
        assert not any(k.startswith(RESET_TOKEN_CACHE_PREFIX) for k in cache._values)

    async def test_case_insensitive_lookup(
        self,
        security_manager: SecurityManager,
        user: Dict[str, Any],
        token_capture: List[str],
    ) -> None:
        await security_manager.request_password_reset(email="ALICE@example.TEST")
        assert len(token_capture) == 1

    async def test_requires_an_identifier(self, security_manager: SecurityManager) -> None:
        with pytest.raises(ValueError):
            await security_manager.request_password_reset()


class TestResetConsumption:
    async def _issue(self, security_manager: SecurityManager) -> str:
        seen: List[str] = []
        original = security.generate_reset_token

        def wrapper() -> str:
            token = original()
            seen.append(token)
            return token

        async def _noop_send(**kwargs):
            return {"sent": False, "reason": "fake"}

        security_manager._email.send = _noop_send  # type: ignore[method-assign]
        import authy_package.utils.security as sec

        old = sec.generate_reset_token
        sec.generate_reset_token = wrapper
        try:
            await security_manager.request_password_reset(email="Alice@example.test")
        finally:
            sec.generate_reset_token = old
        return seen[0]

    async def test_validate_peek_does_not_consume(
        self, security_manager: SecurityManager, user: Dict[str, Any]
    ) -> None:
        token = await self._issue(security_manager)
        assert await security_manager.validate_reset_token(token) is not None
        assert await security_manager.validate_reset_token(token) is not None

    async def test_single_use_consume(
        self, security_manager: SecurityManager, user: Dict[str, Any]
    ) -> None:
        token = await self._issue(security_manager)
        first = await security_manager.consume_reset_token(token)
        assert first is not None
        second = await security_manager.consume_reset_token(token)
        assert second is None

    async def test_invalid_token_returns_none(
        self, security_manager: SecurityManager
    ) -> None:
        assert await security_manager.validate_reset_token(generate_reset_token()) is None
        assert await security_manager.consume_reset_token(generate_reset_token()) is None

    async def test_empty_token_raises_value_error(
        self, security_manager: SecurityManager
    ) -> None:
        with pytest.raises(ValueError):
            await security_manager.validate_reset_token("")
        with pytest.raises(ValueError):
            await security_manager.consume_reset_token("")


class TestResetPassword:
    async def _issue(self, security_manager: SecurityManager) -> str:
        import authy_package.utils.security as sec

        seen: List[str] = []
        original = sec.generate_reset_token

        def wrapper() -> str:
            token = original()
            seen.append(token)
            return token

        sec.generate_reset_token = wrapper
        try:
            await security_manager.request_password_reset(email="alice@example.test")
        finally:
            sec.generate_reset_token = original
        return seen[0]

    async def test_full_lifecycle_updates_password_and_revokes_sessions(
        self, security_manager: SecurityManager, db, user: Dict[str, Any]
    ) -> None:
        await db.save_session({"id": "s1", "user_id": user["id"], "status": "active"})
        await db.save_session({"id": "s2", "user_id": user["id"], "status": "active"})

        token = await self._issue(security_manager)
        result = await security_manager.reset_password(token, "Brand-New-Pass-2")
        assert result["message"] == "Password updated successfully."

        updated = await db.get_user_by_id(user["id"])
        assert verify_password("Brand-New-Pass-2", updated["hashed_password"]) is True
        assert verify_password("Original-Pass-1", updated["hashed_password"]) is False
        assert await db.get_active_sessions(user["id"]) == []

    async def test_token_reuse_after_reset_fails(
        self, security_manager: SecurityManager, user: Dict[str, Any]
    ) -> None:
        token = await self._issue(security_manager)
        await security_manager.reset_password(token, "Brand-New-Pass-2")
        with pytest.raises(AuthenticationError) as excinfo:
            await security_manager.reset_password(token, "Another-Pass-3")
        assert excinfo.value.code == "reset_token_invalid"

    async def test_invalid_token_raises_authentication_error(
        self, security_manager: SecurityManager
    ) -> None:
        with pytest.raises(AuthenticationError):
            await security_manager.reset_password(
                generate_reset_token(), "Brand-New-Pass-2"
            )

    async def test_empty_password_rejected(
        self, security_manager: SecurityManager, user: Dict[str, Any]
    ) -> None:
        token = await self._issue(security_manager)
        with pytest.raises(ValueError):
            await security_manager.reset_password(token, "")
        # Token was NOT consumed by the failed attempt's validation error.
        assert await security_manager.validate_reset_token(token) is not None


class TestEmailUnconfigured:
    async def test_no_op_with_warning_when_email_disabled(
        self, security_manager: SecurityManager, user: Dict[str, Any], token_capture
    ) -> None:
        assert security_manager.email_configured is False
        result = await security_manager.request_password_reset(email="alice@example.test")
        # Flow still succeeds at rest even without email transport.
        assert "reset" in result["message"].lower()
        assert len(token_capture) == 1
