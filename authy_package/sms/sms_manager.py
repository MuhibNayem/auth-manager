"""
SMS Manager for Authy Package.

Handles verification code generation, sending, and validation with rate limiting,
expiration, and attempt tracking.

Usage:
    from authy_package.sms import SMSManager, TwilioProvider
    
    # Setup provider
    provider = TwilioProvider.from_env()
    
    # Create manager with cache (Redis recommended)
    sms_manager = SMSManager(
        provider=provider,
        cache=redis_cache_instance,
        code_length=6,
        expiration_seconds=300,
        max_attempts=3
    )
    
    # Send verification code
    result = await sms_manager.send_verification_code("+1234567890")
    
    # Verify code
    is_valid = await sms_manager.verify_code("+1234567890", "123456")
"""

import random
import string
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from .abstract_provider import (
    AbstractSMSProvider,
    SMSResponse,
    SMSProviderError,
    VerificationCodeExpiredError,
    InvalidVerificationCodeError,
    TooManyAttemptsError
)


class SMSManager:
    """
    Manages SMS verification codes with security features.
    
    Features:
    - Random code generation (configurable length)
    - Code expiration
    - Attempt limiting to prevent brute force
    - Rate limiting per phone number
    - Template customization
    - Delivery tracking
    """
    
    DEFAULT_TEMPLATE = "Your verification code is: {code}. Valid for {minutes} minutes."
    
    def __init__(
        self,
        provider: AbstractSMSProvider,
        cache: Optional[Any] = None,
        code_length: int = 6,
        expiration_seconds: int = 300,  # 5 minutes
        max_attempts: int = 3,
        rate_limit_window_seconds: int = 60,
        max_sends_per_window: int = 3,
        template: Optional[str] = None
    ):
        """
        Initialize SMS Manager.
        
        :param provider: SMS provider instance (Twilio, AWS SNS, etc.)
        :param cache: Cache instance for storing codes (Redis recommended)
        :param code_length: Length of verification code (default: 6)
        :param expiration_seconds: Code expiration time in seconds (default: 300)
        :param max_attempts: Maximum verification attempts per code
        :param rate_limit_window_seconds: Time window for rate limiting
        :param max_sends_per_window: Maximum codes that can be sent per window
        :param template: Message template (use {code} and {minutes} placeholders)
        """
        self.provider = provider
        self.cache = cache
        self.code_length = code_length
        self.expiration_seconds = expiration_seconds
        self.max_attempts = max_attempts
        self.rate_limit_window_seconds = rate_limit_window_seconds
        self.max_sends_per_window = max_sends_per_window
        self.template = template or self.DEFAULT_TEMPLATE
        
        # In-memory fallback if no cache provided
        self._memory_store: Dict[str, Dict[str, Any]] = {}
    
    def _generate_code(self) -> str:
        """Generate a random numeric verification code."""
        return ''.join(random.choices(string.digits, k=self.code_length))
    
    def _get_cache_key(self, phone: str, suffix: str = "") -> str:
        """Generate cache key for phone number."""
        base = f"sms:verify:{phone}"
        return f"{base}:{suffix}" if suffix else base
    
    async def _store_in_cache(self, key: str, value: Any, expiration: int):
        """Store value in cache or memory."""
        if self.cache:
            await self.cache.set(key, str(value), expire=expiration)
        else:
            self._memory_store[key] = {
                "value": value,
                "expires_at": datetime.now() + timedelta(seconds=expiration)
            }
    
    async def _get_from_cache(self, key: str) -> Optional[str]:
        """Get value from cache or memory."""
        if self.cache:
            return await self.cache.get(key)
        else:
            record = self._memory_store.get(key)
            if record and datetime.now() < record["expires_at"]:
                return record["value"]
            return None
    
    async def _delete_from_cache(self, key: str):
        """Delete value from cache or memory."""
        if self.cache:
            await self.cache.delete(key)
        else:
            self._memory_store.pop(key, None)
    
    async def _check_rate_limit(self, phone: str) -> bool:
        """Check if phone number is rate limited. Returns True if allowed."""
        key = self._get_cache_key(phone, "rate_limit")
        count = await self._get_from_cache(key)
        
        if count is None:
            # First send in this window
            await self._store_in_cache(key, 1, self.rate_limit_window_seconds)
            return True
        
        current_count = int(count)
        if current_count >= self.max_sends_per_window:
            return False
        
        # Increment counter
        await self._store_in_cache(key, current_count + 1, self.rate_limit_window_seconds)
        return True
    
    async def send_verification_code(
        self,
        phone: str,
        custom_message: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send a verification code to the specified phone number.
        
        :param phone: Phone number in E.164 format (e.g., +1234567890)
        :param custom_message: Optional custom message (overrides template)
        :return: Dictionary with success status and metadata
        :raises: TooManyAttemptsError if rate limited
        """
        # Check rate limit
        if not await self._check_rate_limit(phone):
            raise TooManyAttemptsError(
                f"Too many verification codes sent. Try again in {self.rate_limit_window_seconds} seconds."
            )
        
        # Generate code
        code = self._generate_code()
        
        # Prepare message
        if custom_message:
            message = custom_message.replace("{code}", code)
        else:
            message = self.template.format(
                code=code,
                minutes=self.expiration_seconds // 60
            )
        
        # Send SMS
        response = await self.provider.send_sms(to=phone, body=message)
        
        if response.success:
            # Store code with expiration
            code_key = self._get_cache_key(phone, "code")
            await self._store_in_cache(code_key, code, self.expiration_seconds)
            
            # Reset attempt counter
            attempts_key = self._get_cache_key(phone, "attempts")
            await self._store_in_cache(attempts_key, 0, self.expiration_seconds)
            
            return {
                "success": True,
                "message_id": response.message_id,
                "provider": self.provider.provider_name,
                "expires_in": self.expiration_seconds,
                "phone": phone
            }
        else:
            return {
                "success": False,
                "error": response.error_message,
                "provider": self.provider.provider_name
            }
    
    async def verify_code(self, phone: str, code: str) -> Dict[str, Any]:
        """
        Verify a code entered by the user.
        
        :param phone: Phone number in E.164 format
        :param code: Verification code to check
        :return: Dictionary with verification result
        :raises: VerificationCodeExpiredError if code expired
        :raises: InvalidVerificationCodeError if code is wrong
        :raises: TooManyAttemptsError if max attempts exceeded
        """
        code_key = self._get_cache_key(phone, "code")
        attempts_key = self._get_cache_key(phone, "attempts")
        
        # Get stored code
        stored_code = await self._get_from_cache(code_key)
        
        if stored_code is None:
            raise VerificationCodeExpiredError(
                "Verification code has expired or doesn't exist. Please request a new one."
            )
        
        # Check attempts
        attempts_str = await self._get_from_cache(attempts_key)
        attempts = int(attempts_str) if attempts_str else 0
        
        if attempts >= self.max_attempts:
            # Delete code to prevent further attempts
            await self._delete_from_cache(code_key)
            raise TooManyAttemptsError(
                f"Maximum verification attempts ({self.max_attempts}) exceeded. Please request a new code."
            )
        
        # Verify code
        if code != stored_code:
            # Increment attempts
            await self._store_in_cache(
                attempts_key,
                attempts + 1,
                self.expiration_seconds
            )
            
            remaining_attempts = self.max_attempts - attempts - 1
            raise InvalidVerificationCodeError(
                f"Invalid verification code. {remaining_attempts} attempts remaining."
            )
        
        # Success! Clean up
        await self._delete_from_cache(code_key)
        await self._delete_from_cache(attempts_key)
        
        return {
            "success": True,
            "verified": True,
            "phone": phone
        }
    
    async def resend_code(self, phone: str) -> Dict[str, Any]:
        """
        Resend a verification code to the same phone number.
        
        This generates a new code and invalidates the previous one.
        
        :param phone: Phone number in E.164 format
        :return: Dictionary with send result
        """
        # Invalidate existing code
        code_key = self._get_cache_key(phone, "code")
        await self._delete_from_cache(code_key)
        
        # Send new code
        return await self.send_verification_code(phone)
    
    async def get_delivery_status(self, message_id: str) -> str:
        """
        Get delivery status of a sent message.
        
        :param message_id: Message ID from send_verification_code response
        :return: Status string (sent, delivered, failed, unknown)
        """
        return await self.provider.check_delivery_status(message_id)
