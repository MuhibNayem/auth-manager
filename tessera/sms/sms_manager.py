"""SMS verification manager (CONTRACTS.md §0, §3, §3.1).

Handles verification-code generation, delivery and verification:

- Codes are generated with :mod:`secrets` (cryptographically secure; §0.3).
- Verification compares sha256 digests via :func:`hmac.compare_digest` (§0.4);
  only the code hash is persisted, never the plaintext code.
- Send rate limiting is a FIXED window: the counter TTL is set exactly once,
  on the first increment of the window (no sliding reset).
- Verification attempts are capped; the record is deleted once exhausted.
- Code lifetime comes from configuration (``expiration_seconds``).
- State persists under the §3.1 cache key ``tessera:sms:{phone}`` as JSON:
  ``{code_hash, attempts, expires_at, last_sent_at}``.

Usage:
    provider = TwilioProvider.from_env()
    manager = SMSManager(provider=provider, cache=cache)  # AbstractCache
    await manager.send_verification_code("+15551234567")
    result = await manager.verify_code("+15551234567", "123456")
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import string
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from tessera.cache import AbstractCache, InMemoryCache
from tessera.config import SMSConfig
from tessera.errors import ProviderError

from .abstract_provider import (
    AbstractSMSProvider,
    InvalidVerificationCodeError,
    SMSProviderError,
    TooManyAttemptsError,
    VerificationCodeExpiredError,
)

logger = logging.getLogger("tessera.sms.manager")

__all__ = ["SMSManager"]

_DIGITS = string.digits


def _utcnow() -> datetime:
    """Timezone-aware UTC now (§0.5)."""
    return datetime.now(timezone.utc)


def _hash_code(code: str) -> str:
    """sha256 hex digest of a verification code (codes never stored raw)."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


class SMSManager:
    """Manages SMS verification codes with security controls.

    Features:
    - CSPRNG code generation (configurable length)
    - Hashed-at-rest codes with constant-time comparison
    - Code expiration from configuration
    - Verification attempt cap
    - Fixed-window send rate limiting (TTL set once per window)
    - Delivery status passthrough to the provider
    """

    DEFAULT_TEMPLATE = "Your verification code is: {code}. Valid for {minutes} minutes."

    def __init__(
        self,
        provider: AbstractSMSProvider,
        cache: Optional[AbstractCache] = None,
        *,
        code_length: int = 6,
        expiration_seconds: int = 300,
        max_attempts: int = 3,
        rate_limit_window_seconds: int = 60,
        max_sends_per_window: int = 3,
        template: Optional[str] = None,
    ) -> None:
        """Initialize the manager.

        Args:
            provider: SMS provider instance (Twilio, AWS SNS, ...).
            cache: AbstractCache implementation; defaults to a private
                :class:`InMemoryCache` (single-process only).
            code_length: Length of the numeric verification code.
            expiration_seconds: Code lifetime in seconds.
            max_attempts: Maximum verification attempts per code.
            rate_limit_window_seconds: Fixed window for send rate limiting.
            max_sends_per_window: Maximum sends allowed per window.
            template: Message template with ``{code}``/``{minutes}`` fields.
        """
        if code_length < 4:
            raise ValueError("code_length must be at least 4")
        if expiration_seconds <= 0:
            raise ValueError("expiration_seconds must be positive")
        if max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if rate_limit_window_seconds <= 0:
            raise ValueError("rate_limit_window_seconds must be positive")
        if max_sends_per_window <= 0:
            raise ValueError("max_sends_per_window must be positive")

        self.provider = provider
        self.cache: AbstractCache = cache if cache is not None else InMemoryCache()
        self.code_length = code_length
        self.expiration_seconds = expiration_seconds
        self.max_attempts = max_attempts
        self.rate_limit_window_seconds = rate_limit_window_seconds
        self.max_sends_per_window = max_sends_per_window
        self.template = template or self.DEFAULT_TEMPLATE

    @classmethod
    def from_config(
        cls,
        provider: AbstractSMSProvider,
        cache: Optional[AbstractCache],
        config: SMSConfig,
    ) -> "SMSManager":
        """Build a manager from an :class:`~tessera.config.SMSConfig`."""
        return cls(
            provider,
            cache,
            code_length=config.code_length,
            expiration_seconds=config.expiration_seconds,
            max_attempts=config.max_attempts,
            rate_limit_window_seconds=config.rate_limit_window_seconds,
            max_sends_per_window=config.max_sends_per_window,
        )

    # -- key schema (§3.1) ----------------------------------------------------

    @staticmethod
    def _state_key(phone: str) -> str:
        """State record key: ``tessera:sms:{phone}`` (§3.1)."""
        return f"tessera:sms:{phone}"

    @staticmethod
    def _rate_limit_key(phone: str) -> str:
        """Fixed-window send counter key (§3.1 ratelimit namespace)."""
        return f"tessera:ratelimit:sms:{phone}"

    # -- code generation --------------------------------------------------------

    def _generate_code(self) -> str:
        """Generate a cryptographically secure numeric code (§0.3)."""
        return "".join(secrets.choice(_DIGITS) for _ in range(self.code_length))

    # -- rate limiting (fixed window) ---------------------------------------------

    async def _check_send_rate_limit(self, phone: str) -> None:
        """Enforce the fixed-window send limit for ``phone``.

        The counter is created with ``incr`` and its TTL is set ONCE, on the
        first increment of the window. Later increments never touch the TTL,
        so the window cannot slide forward.

        Raises:
            TooManyAttemptsError: When the window's send budget is exhausted.
        """
        key = self._rate_limit_key(phone)
        count = await self.cache.incr(key)
        if count == 1:
            await self.cache.expire(key, self.rate_limit_window_seconds)
        if count > self.max_sends_per_window:
            remaining = await self.cache.ttl(key)
            retry_after = remaining if remaining > 0 else self.rate_limit_window_seconds
            logger.warning("SMS send rate limit exceeded for %s", phone)
            raise TooManyAttemptsError(
                f"Too many verification codes sent. Try again in {retry_after} seconds.",
                retry_after=retry_after,
            )

    # -- public API -----------------------------------------------------------------

    async def send_verification_code(
        self,
        phone: str,
        custom_message: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send a verification code to ``phone`` (E.164 format).

        Returns:
            Dict with ``success`` and provider metadata. On upstream provider
            failure the dict carries ``success=False`` and the provider error
            message (delivery passthrough); no state is stored.

        Raises:
            TooManyAttemptsError: When the send rate limit is exceeded.
            ValueError: When ``phone`` is empty.
        """
        if not phone or not phone.strip():
            raise ValueError("phone must be a non-empty E.164 number")

        await self._check_send_rate_limit(phone)

        code = self._generate_code()
        if custom_message:
            message = custom_message.replace("{code}", code)
        else:
            message = self.template.format(
                code=code, minutes=max(1, self.expiration_seconds // 60)
            )

        try:
            response = await self.provider.send_sms(to=phone, body=message)
        except ProviderError as exc:
            logger.warning("SMS provider failure for %s: %s", phone, exc.message)
            return {
                "success": False,
                "error": exc.message,
                "provider": self.provider.provider_name,
            }

        if not response.success:
            return {
                "success": False,
                "error": response.error_message or "unknown provider error",
                "provider": self.provider.provider_name,
            }

        now = _utcnow()
        record = {
            "code_hash": _hash_code(code),
            "attempts": 0,
            "expires_at": (
                now.timestamp() + self.expiration_seconds
            ),
            "last_sent_at": now.isoformat(),
        }
        await self.cache.set_json(
            self._state_key(phone), record, ttl_seconds=self.expiration_seconds
        )

        return {
            "success": True,
            "message_id": response.message_id,
            "provider": self.provider.provider_name,
            "expires_in": self.expiration_seconds,
            "phone": phone,
        }

    async def verify_code(self, phone: str, code: str) -> Dict[str, Any]:
        """Verify a user-supplied code for ``phone``.

        Raises:
            VerificationCodeExpiredError: No live code exists for ``phone``.
            TooManyAttemptsError: The attempt cap was reached.
            InvalidVerificationCodeError: The code does not match.
        """
        state_key = self._state_key(phone)
        record = await self.cache.get_json(state_key)

        if not record or not record.get("code_hash"):
            raise VerificationCodeExpiredError(
                "Verification code has expired or doesn't exist. "
                "Please request a new one."
            )

        expires_at = record.get("expires_at")
        if expires_at is not None and _utcnow().timestamp() >= float(expires_at):
            await self.cache.delete(state_key)
            raise VerificationCodeExpiredError(
                "Verification code has expired. Please request a new one."
            )

        attempts = int(record.get("attempts", 0))
        if attempts >= self.max_attempts:
            await self.cache.delete(state_key)
            raise TooManyAttemptsError(
                f"Maximum verification attempts ({self.max_attempts}) exceeded. "
                "Please request a new code.",
                retry_after=self.expiration_seconds,
            )

        stored_hash = str(record["code_hash"])
        if not hmac.compare_digest(_hash_code(code), stored_hash):
            attempts += 1
            record["attempts"] = attempts
            # Preserve the remaining lifetime of the original window.
            remaining = await self.cache.ttl(state_key)
            ttl = remaining if remaining > 0 else self.expiration_seconds
            await self.cache.set_json(state_key, record, ttl_seconds=ttl)

            if attempts >= self.max_attempts:
                await self.cache.delete(state_key)
                raise TooManyAttemptsError(
                    f"Maximum verification attempts ({self.max_attempts}) exceeded. "
                    "Please request a new code.",
                    retry_after=self.expiration_seconds,
                )

            remaining_attempts = self.max_attempts - attempts
            raise InvalidVerificationCodeError(
                f"Invalid verification code. {remaining_attempts} attempts remaining."
            )

        # Success: single-use code, remove all state for this phone.
        await self.cache.delete(state_key)
        return {"success": True, "verified": True, "phone": phone}

    async def resend_code(self, phone: str) -> Dict[str, Any]:
        """Send a fresh code, invalidating any previous one."""
        await self.cache.delete(self._state_key(phone))
        return await self.send_verification_code(phone)

    async def get_delivery_status(self, message_id: str) -> str:
        """Passthrough to the provider's delivery status API."""
        try:
            return await self.provider.check_delivery_status(message_id)
        except SMSProviderError:
            raise
        except Exception as exc:  # upstream/SDK failures map to ProviderError (§1)
            raise SMSProviderError(
                f"Failed to check delivery status: {exc}"
            ) from exc
