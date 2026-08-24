"""Typed domain errors for the Authy package.

Canonical hierarchy per docs/CONTRACTS.md §1. Every domain failure raises a
subclass of :class:`AuthyError` carrying a stable machine-readable ``code``
and a human-readable ``message``. HTTP layers map these to status codes
(400/401/403/404/409/429/500, 502 for :class:`ProviderError`).
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "AuthyError",
    "ConfigError",
    "AuthenticationError",
    "AuthorizationError",
    "RateLimitError",
    "NotFoundError",
    "IntegrityError",
    "ProviderError",
    "DatabaseError",
    "TokenError",
]


class AuthyError(Exception):
    """Base class for all Authy domain errors.

    Carries ``.code`` (stable machine-readable identifier) and ``.message``
    (human-readable detail). Subclasses set ``default_code``.
    """

    default_code: str = "authy_error"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.message: str = message
        self.code: str = code if code is not None else self.default_code

    def to_dict(self) -> dict[str, Any]:
        """Serialize the error for API responses."""
        return {"error": self.code, "message": self.message}

    def __str__(self) -> str:
        return self.message


class ConfigError(AuthyError):
    """Invalid or missing configuration."""

    default_code = "config_error"


class AuthenticationError(AuthyError):
    """Bad credentials, invalid session, or locked account."""

    default_code = "authentication_failed"


class AuthorizationError(AuthyError):
    """Authenticated but insufficient permissions."""

    default_code = "authorization_failed"


class RateLimitError(AuthyError):
    """Too many attempts; carries ``retry_after`` seconds."""

    default_code = "rate_limited"

    def __init__(
        self,
        message: str,
        *,
        retry_after: int,
        code: str | None = None,
    ) -> None:
        super().__init__(message, code=code)
        self.retry_after: int = int(retry_after)

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["retry_after"] = self.retry_after
        return data


class NotFoundError(AuthyError):
    """Requested resource does not exist."""

    default_code = "not_found"


class IntegrityError(AuthyError):
    """Duplicate/foreign-key style constraint violation."""

    default_code = "integrity_error"


class ProviderError(AuthyError):
    """Upstream provider failure (email, SMS, social, IdP...)."""

    default_code = "provider_error"


class DatabaseError(AuthyError):
    """Persistence failure."""

    default_code = "database_error"


class TokenError(AuthyError):
    """Expired, invalid, or wrong-type token."""

    default_code = "token_error"
