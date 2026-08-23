"""SMS provider abstraction (CONTRACTS.md §0/§1).

Vendor-agnostic async interface for SMS providers (Twilio, AWS SNS, ...).
The legacy exception names are kept for backwards compatibility but are now
subclasses of the typed :mod:`authy_package.errors` hierarchy (§1), so HTTP
layers can map them uniformly (ProviderError -> 502, RateLimitError -> 429).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

from authy_package.errors import (
    AuthenticationError,
    ProviderError,
    RateLimitError,
)

__all__ = [
    "AbstractSMSProvider",
    "SMSMessage",
    "SMSResponse",
    "SMSProviderError",
    "VerificationCodeExpiredError",
    "InvalidVerificationCodeError",
    "TooManyAttemptsError",
]


@dataclass
class SMSMessage:
    """Represents an SMS message."""

    to: str
    body: str
    from_number: Optional[str] = None
    status: str = "pending"  # pending, sent, delivered, failed
    error_message: Optional[str] = None


@dataclass
class SMSResponse:
    """Response from an SMS provider."""

    success: bool
    message_id: Optional[str] = None
    status: str = "unknown"
    error_message: Optional[str] = None
    raw_response: Optional[Dict[str, Any]] = None


class AbstractSMSProvider(ABC):
    """Abstract base class for SMS providers."""

    @abstractmethod
    async def send_sms(
        self, to: str, body: str, from_number: Optional[str] = None
    ) -> SMSResponse:
        """Send an SMS message.

        Args:
            to: Recipient phone number in E.164 format (e.g. +1234567890).
            body: Message body text.
            from_number: Sender phone number (when the provider supports it).

        Returns:
            SMSResponse with success status and provider message id.

        Raises:
            ProviderError: On upstream provider failure after retries.
        """

    @abstractmethod
    async def check_delivery_status(self, message_id: str) -> str:
        """Return the delivery status string for a sent message."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the name of the SMS provider."""


class SMSProviderError(ProviderError):
    """Upstream SMS provider failure (§1 ProviderError)."""

    default_code = "sms_provider_error"


class VerificationCodeExpiredError(AuthenticationError):
    """The verification code expired or was never issued."""

    default_code = "sms_code_expired"


class InvalidVerificationCodeError(AuthenticationError):
    """The supplied verification code does not match."""

    default_code = "sms_code_invalid"


class TooManyAttemptsError(RateLimitError):
    """Too many send or verify attempts; carries ``retry_after``."""

    default_code = "sms_too_many_attempts"

    def __init__(
        self,
        message: str,
        *,
        retry_after: int = 0,
        code: Optional[str] = None,
    ) -> None:
        super().__init__(message, retry_after=retry_after, code=code)
