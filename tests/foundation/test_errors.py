"""Tests for the §1 error hierarchy."""

from __future__ import annotations

import pytest

from tessera.errors import (
    AuthenticationError,
    AuthorizationError,
    TesseraError,
    ConfigError,
    DatabaseError,
    IntegrityError,
    NotFoundError,
    ProviderError,
    RateLimitError,
    TokenError,
)


def test_base_error_carries_code_and_message() -> None:
    err = TesseraError("something broke")
    assert err.message == "something broke"
    assert err.code == "tessera_error"
    assert str(err) == "something broke"


def test_custom_code_overrides_default() -> None:
    err = AuthenticationError("nope", code="custom_code")
    assert err.code == "custom_code"


@pytest.mark.parametrize(
    "cls,expected_code",
    [
        (ConfigError, "config_error"),
        (AuthenticationError, "authentication_failed"),
        (AuthorizationError, "authorization_failed"),
        (NotFoundError, "not_found"),
        (IntegrityError, "integrity_error"),
        (ProviderError, "provider_error"),
        (DatabaseError, "database_error"),
        (TokenError, "token_error"),
    ],
)
def test_subclass_default_codes(cls: type, expected_code: str) -> None:
    err = cls("detail")
    assert isinstance(err, TesseraError)
    assert err.code == expected_code
    assert err.message == "detail"


def test_rate_limit_error_retry_after() -> None:
    err = RateLimitError("slow down", retry_after=42)
    assert err.retry_after == 42
    assert err.code == "rate_limited"
    assert isinstance(err, TesseraError)


def test_to_dict_serialization() -> None:
    err = RateLimitError("slow down", retry_after=7)
    assert err.to_dict() == {
        "error": "rate_limited",
        "message": "slow down",
        "retry_after": 7,
    }
    plain = NotFoundError("gone").to_dict()
    assert plain == {"error": "not_found", "message": "gone"}
