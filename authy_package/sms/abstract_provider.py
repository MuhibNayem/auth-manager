"""
SMS Provider Abstraction Layer for Authy Package.

This module provides a vendor-agnostic interface for SMS providers,
allowing easy integration with Twilio, Vonage, AWS SNS, MessageBird, etc.

Usage:
    from authy_package.sms import TwilioProvider, SMSManager
    
    # Configure your provider
    provider = TwilioProvider(
        account_sid="ACxxxx",
        auth_token="your-token",
        from_number="+1234567890"
    )
    
    # Or use environment variables
    provider = TwilioProvider.from_env()
    
    # Create SMS manager
    sms_manager = SMSManager(provider=provider, cache=cache_instance)
    
    # Send verification code
    await sms_manager.send_verification_code(phone="+1234567890")
    
    # Verify code
    is_valid = await sms_manager.verify_code(phone="+1234567890", code="123456")
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Protocol
from dataclasses import dataclass
import asyncio
import random
import os


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
    """Response from SMS provider."""
    success: bool
    message_id: Optional[str] = None
    status: str = "unknown"
    error_message: Optional[str] = None
    raw_response: Optional[Dict[str, Any]] = None


class AbstractSMSProvider(ABC):
    """
    Abstract base class for SMS providers.
    
    Implement this class to add support for new SMS providers.
    """
    
    @abstractmethod
    async def send_sms(self, to: str, body: str, from_number: Optional[str] = None) -> SMSResponse:
        """
        Send an SMS message.
        
        :param to: Recipient phone number in E.164 format (e.g., +1234567890)
        :param body: Message body text
        :param from_number: Sender phone number (if supported by provider)
        :return: SMSResponse with success status and message ID
        """
        pass
    
    @abstractmethod
    async def check_delivery_status(self, message_id: str) -> str:
        """
        Check the delivery status of a sent message.
        
        :param message_id: The message ID returned from send_sms
        :return: Status string (sent, delivered, failed, etc.)
        """
        pass
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the name of the SMS provider."""
        pass


class SMSProviderError(Exception):
    """Exception raised when SMS provider operations fail."""
    pass


class VerificationCodeExpiredError(Exception):
    """Exception raised when verification code has expired."""
    pass


class InvalidVerificationCodeError(Exception):
    """Exception raised when verification code is invalid."""
    pass


class TooManyAttemptsError(Exception):
    """Exception raised when too many verification attempts have been made."""
    pass
