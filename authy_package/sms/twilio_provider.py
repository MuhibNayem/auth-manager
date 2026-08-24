"""Twilio SMS provider (CONTRACTS.md §0/§1).

Async wrapper over the synchronous Twilio SDK (executed in a thread pool).
Credentials come exclusively from constructor arguments or environment
variables (``TWILIO_ACCOUNT_SID`` / ``TWILIO_AUTH_TOKEN`` /
``TWILIO_FROM_NUMBER``); nothing is hardcoded (§0.8).

Upstream failures raise :class:`SMSProviderError` (§1 ``ProviderError``)
after the retry budget is exhausted.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Optional

try:
    from twilio.rest import Client as TwilioClient
    from twilio.base.exceptions import TwilioRestException, TwilioException

    TWILIO_AVAILABLE = True
except ImportError:  # §0.9 — module imports cleanly without the SDK
    TWILIO_AVAILABLE = False
    TwilioClient = None  # type: ignore[assignment]
    TwilioRestException = None  # type: ignore[assignment,misc]
    TwilioException = None  # type: ignore[assignment,misc]

import os

from .abstract_provider import AbstractSMSProvider, SMSProviderError, SMSResponse

logger = logging.getLogger("authy.sms.twilio")

__all__ = ["TwilioConfig", "TwilioProvider", "TWILIO_AVAILABLE"]


@dataclass
class TwilioConfig:
    """Twilio configuration (credentials via env only; §0.8)."""

    account_sid: str
    auth_token: str
    from_number: str
    messaging_service_sid: Optional[str] = None

    @classmethod
    def from_env(cls) -> "TwilioConfig":
        """Load configuration from environment variables."""
        account_sid = os.getenv("TWILIO_ACCOUNT_SID")
        auth_token = os.getenv("TWILIO_AUTH_TOKEN")
        from_number = os.getenv("TWILIO_FROM_NUMBER")
        messaging_service_sid = os.getenv("TWILIO_MESSAGING_SERVICE_SID")

        if not account_sid or not auth_token or not from_number:
            raise ValueError(
                "Twilio configuration missing. Set TWILIO_ACCOUNT_SID, "
                "TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER"
            )

        return cls(
            account_sid=account_sid,
            auth_token=auth_token,
            from_number=from_number,
            messaging_service_sid=messaging_service_sid,
        )


class TwilioProvider(AbstractSMSProvider):
    """Twilio SMS provider with retries and typed error mapping."""

    def __init__(
        self,
        account_sid: Optional[str] = None,
        auth_token: Optional[str] = None,
        from_number: Optional[str] = None,
        messaging_service_sid: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ) -> None:
        """Initialize the provider.

        Args:
            account_sid/auth_token/from_number: Explicit credentials; when
                omitted they are read from the environment.
            messaging_service_sid: Optional Twilio Messaging Service SID.
            max_retries: Retry attempts for transient failures.
            retry_delay: Base delay (seconds) for exponential backoff.

        Raises:
            ImportError: When the ``twilio`` package is not installed.
            ValueError: When credentials are missing.
        """
        if not TWILIO_AVAILABLE:
            raise ImportError(
                "Twilio library not installed. Install with: pip install twilio"
            )

        if account_sid and auth_token and from_number:
            self.config = TwilioConfig(
                account_sid=account_sid,
                auth_token=auth_token,
                from_number=from_number,
                messaging_service_sid=messaging_service_sid,
            )
        else:
            self.config = TwilioConfig.from_env()

        self._client: Optional[Any] = None
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    @property
    def client(self) -> Any:
        """Lazily constructed Twilio SDK client."""
        if self._client is None:
            self._client = TwilioClient(
                self.config.account_sid, self.config.auth_token
            )
        return self._client

    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "Twilio"

    async def send_sms(
        self, to: str, body: str, from_number: Optional[str] = None
    ) -> SMSResponse:
        """Send an SMS via Twilio.

        Raises:
            SMSProviderError: On upstream failure after retries (§1).
        """
        last_error: Optional[str] = None

        for attempt in range(self.max_retries + 1):
            try:
                loop = asyncio.get_running_loop()
                message = await loop.run_in_executor(
                    None, self._send_sms_sync, to, body, from_number
                )
                return SMSResponse(
                    success=True,
                    message_id=message.sid,
                    status=message.status,
                    raw_response={"date_created": str(message.date_created)},
                )
            except TwilioRestException as exc:
                # ``exc.code`` may be None for some upstream payloads — guard it.
                code = getattr(exc, "code", None)
                last_error = f"Twilio API error: {code} - {exc.msg}"
                if code is not None and 400 <= int(code) < 500:
                    break  # client errors do not benefit from retries
            except TwilioException as exc:
                last_error = f"Twilio error: {exc}"
            except Exception as exc:  # unexpected SDK/network failure
                last_error = f"Unexpected error: {exc}"

            if attempt < self.max_retries:
                await asyncio.sleep(self.retry_delay * (2**attempt))

        raise SMSProviderError(
            f"Twilio send failed: {last_error or 'unknown error'}"
        )

    def _send_sms_sync(
        self, to: str, body: str, from_number: Optional[str] = None
    ) -> Any:
        """Synchronous Twilio send (runs in the executor)."""
        if self.config.messaging_service_sid:
            return self.client.messages.create(
                body=body,
                messaging_service_sid=self.config.messaging_service_sid,
                to=to,
            )
        sender = from_number or self.config.from_number
        return self.client.messages.create(body=body, from_=sender, to=to)

    async def check_delivery_status(self, message_id: str) -> str:
        """Return Twilio's delivery status for ``message_id``.

        Raises:
            SMSProviderError: When the status lookup fails.
        """
        try:
            loop = asyncio.get_running_loop()
            message = await loop.run_in_executor(
                None, lambda: self.client.messages(message_id).fetch()
            )
            return str(message.status)
        except Exception as exc:
            raise SMSProviderError(
                f"Failed to check delivery status: {exc}"
            ) from exc

    @classmethod
    def from_env(cls, **kwargs: Any) -> "TwilioProvider":
        """Create a provider from environment variables."""
        config = TwilioConfig.from_env()
        return cls(
            account_sid=kwargs.get("account_sid", config.account_sid),
            auth_token=kwargs.get("auth_token", config.auth_token),
            from_number=kwargs.get("from_number", config.from_number),
            messaging_service_sid=kwargs.get(
                "messaging_service_sid", config.messaging_service_sid
            ),
            max_retries=kwargs.get("max_retries", 3),
            retry_delay=kwargs.get("retry_delay", 1.0),
        )
