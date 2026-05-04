"""
Twilio SMS Provider Implementation for Authy Package.

Enterprise-grade Twilio integration with async support, retry logic, and comprehensive error handling.

Configuration:
    Option 1 - Direct initialization:
        provider = TwilioProvider(
            account_sid="ACxxxxxxxxxxxxx",
            auth_token="your_auth_token",
            from_number="+1234567890"
        )
    
    Option 2 - Environment variables (recommended):
        # Set these in your .env or environment
        TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxx
        TWILIO_AUTH_TOKEN=your_auth_token
        TWILIO_FROM_NUMBER=+1234567890
        
        provider = TwilioProvider.from_env()

Usage:
    response = await provider.send_sms(
        to="+1987654321",
        body="Your verification code is: 123456"
    )
    
    if response.success:
        print(f"Message sent! ID: {response.message_id}")
    else:
        print(f"Failed: {response.error_message}")
"""

import os
from typing import Optional, Dict, Any
import asyncio
from dataclasses import dataclass

try:
    from twilio.rest import Client as TwilioClient
    from twilio.base.exceptions import TwilioRestException, TwilioException
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False
    TwilioClient = None
    TwilioRestException = Exception
    TwilioException = Exception

from .abstract_provider import AbstractSMSProvider, SMSResponse, SMSProviderError


@dataclass
class TwilioConfig:
    """Twilio configuration."""
    account_sid: str
    auth_token: str
    from_number: str
    messaging_service_sid: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> 'TwilioConfig':
        """Load configuration from environment variables."""
        account_sid = os.getenv("TWILIO_ACCOUNT_SID")
        auth_token = os.getenv("TWILIO_AUTH_TOKEN")
        from_number = os.getenv("TWILIO_FROM_NUMBER")
        messaging_service_sid = os.getenv("TWILIO_MESSAGING_SERVICE_SID")
        
        if not account_sid or not auth_token or not from_number:
            raise ValueError(
                "Twilio configuration missing. Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM_NUMBER"
            )
        
        return cls(
            account_sid=account_sid,
            auth_token=auth_token,
            from_number=from_number,
            messaging_service_sid=messaging_service_sid
        )


class TwilioProvider(AbstractSMSProvider):
    """
    Twilio SMS provider implementation.
    
    Features:
    - Async support with thread pool executor
    - Automatic retry on transient failures
    - Comprehensive error handling
    - Support for both phone numbers and messaging services
    - Delivery status tracking
    """
    
    def __init__(
        self,
        account_sid: Optional[str] = None,
        auth_token: Optional[str] = None,
        from_number: Optional[str] = None,
        messaging_service_sid: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: float = 1.0
    ):
        """
        Initialize Twilio provider.
        
        :param account_sid: Twilio Account SID
        :param auth_token: Twilio Auth Token
        :param from_number: Sender phone number (E.164 format)
        :param messaging_service_sid: Optional Twilio Messaging Service SID
        :param max_retries: Maximum number of retry attempts
        :param retry_delay: Delay between retries in seconds
        """
        if not TWILIO_AVAILABLE:
            raise ImportError(
                "Twilio library not installed. Install with: pip install twilio"
            )
        
        # Load from config or environment
        if account_sid and auth_token and from_number:
            self.config = TwilioConfig(
                account_sid=account_sid,
                auth_token=auth_token,
                from_number=from_number,
                messaging_service_sid=messaging_service_sid
            )
        else:
            self.config = TwilioConfig.from_env()
        
        self._client: Optional[TwilioClient] = None
        self.max_retries = max_retries
        self.retry_delay = retry_delay
    
    @property
    def client(self) -> TwilioClient:
        """Lazy initialization of Twilio client."""
        if self._client is None:
            self._client = TwilioClient(
                self.config.account_sid,
                self.config.auth_token
            )
        return self._client
    
    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "Twilio"
    
    async def send_sms(
        self,
        to: str,
        body: str,
        from_number: Optional[str] = None
    ) -> SMSResponse:
        """
        Send an SMS message via Twilio.
        
        :param to: Recipient phone number in E.164 format
        :param body: Message body text
        :param from_number: Optional sender number (overrides default)
        :return: SMSResponse with success status
        """
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                # Run synchronous Twilio call in thread pool
                loop = asyncio.get_event_loop()
                message = await loop.run_in_executor(
                    None,
                    self._send_sms_sync,
                    to,
                    body,
                    from_number
                )
                
                return SMSResponse(
                    success=True,
                    message_id=message.sid,
                    status=message.status,
                    raw_response={"date_created": str(message.date_created)}
                )
                
            except TwilioRestException as e:
                last_error = f"Twilio API error: {e.code} - {e.msg}"
                # Don't retry on client errors (4xx)
                if 400 <= e.code < 500:
                    break
                    
            except TwilioException as e:
                last_error = f"Twilio error: {str(e)}"
                
            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"
            
            # Retry with exponential backoff
            if attempt < self.max_retries:
                await asyncio.sleep(self.retry_delay * (2 ** attempt))
        
        return SMSResponse(
            success=False,
            error_message=last_error or "Unknown error",
            status="failed"
        )
    
    def _send_sms_sync(
        self,
        to: str,
        body: str,
        from_number: Optional[str] = None
    ):
        """Synchronous Twilio SMS sending (runs in executor)."""
        # Use messaging service if available, otherwise use from_number
        if self.config.messaging_service_sid:
            return self.client.messages.create(
                body=body,
                messaging_service_sid=self.config.messaging_service_sid,
                to=to
            )
        else:
            sender = from_number or self.config.from_number
            return self.client.messages.create(
                body=body,
                from_=sender,
                to=to
            )
    
    async def check_delivery_status(self, message_id: str) -> str:
        """
        Check delivery status of a message.
        
        :param message_id: Twilio message SID
        :return: Status string (queued, sent, delivered, failed, etc.)
        """
        try:
            loop = asyncio.get_event_loop()
            message = await loop.run_in_executor(
                None,
                lambda: self.client.messages(message_id).fetch()
            )
            return message.status
        except Exception as e:
            raise SMSProviderError(f"Failed to check delivery status: {str(e)}")
    
    @classmethod
    def from_env(cls, **kwargs) -> 'TwilioProvider':
        """
        Create TwilioProvider from environment variables.
        
        :param kwargs: Additional arguments to override environment values
        :return: Configured TwilioProvider instance
        """
        config = TwilioConfig.from_env()
        return cls(
            account_sid=kwargs.get('account_sid', config.account_sid),
            auth_token=kwargs.get('auth_token', config.auth_token),
            from_number=kwargs.get('from_number', config.from_number),
            messaging_service_sid=kwargs.get('messaging_service_sid', config.messaging_service_sid),
            max_retries=kwargs.get('max_retries', 3),
            retry_delay=kwargs.get('retry_delay', 1.0)
        )
