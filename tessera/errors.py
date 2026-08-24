"""Typed domain errors for the Tessera package.

Canonical hierarchy per docs/CONTRACTS.md §1. Every domain failure raises a
subclass of :class:`TesseraError` carrying a stable machine-readable ``code``
and a human-readable ``message``. HTTP layers map these to status codes
(400/401/403/404/409/429/500, 502 for :class:`ProviderError`).
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "TesseraError",
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


class TesseraError(Exception):
    """Base class for all Tessera domain errors.

    Carries ``.code`` (stable machine-readable identifier) and ``.message``
    (human-readable detail). Subclasses set ``default_code``.
    """

    default_code: str = "tessera_error"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.message: str = message
        self.code: str = code if code is not None else self.default_code

    def to_dict(self) -> dict[str, Any]:
        """Serialize the error for API responses."""
        return {"error": self.code, "message": self.message}

    def __str__(self) -> str:
        return self.message


class ConfigError(TesseraError):
    """Invalid or missing configuration."""

    default_code = "config_error"


class AuthenticationError(TesseraError):
    """Bad credentials, invalid session, or locked account."""

    default_code = "authentication_failed"


class AuthorizationError(TesseraError):
    """Authenticated but insufficient permissions."""

    default_code = "authorization_failed"


class RateLimitError(TesseraError):
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


class NotFoundError(TesseraError):
    """Requested resource does not exist."""

    default_code = "not_found"


class IntegrityError(TesseraError):
    """Duplicate/foreign-key style constraint violation."""

    default_code = "integrity_error"


class ProviderError(TesseraError):
    """Upstream provider failure (email, SMS, social, IdP...)."""

    default_code = "provider_error"


class DatabaseError(TesseraError):
    """Persistence failure."""

    default_code = "database_error"


class TokenError(TesseraError):
    """Expired, invalid, or wrong-type token."""

    default_code = "token_error"
