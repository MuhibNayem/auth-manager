"""
SMS Module for Authy Package.

Provides vendor-agnostic SMS authentication with support for multiple providers.

Quick Start:
    from authy_package.sms import SMSManager, TwilioProvider
    
    # Initialize provider (uses environment variables)
    provider = TwilioProvider.from_env()
    
    # Create manager
    sms_manager = SMSManager(provider=provider, cache=redis_cache)
    
    # Send verification code
    await sms_manager.send_verification_code("+1234567890")
    
    # Verify code
    result = await sms_manager.verify_code("+1234567890", "123456")

Environment Variables:
    # Twilio
    TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxx
    TWILIO_AUTH_TOKEN=your_auth_token
    TWILIO_FROM_NUMBER=+1234567890
    
    # AWS SNS (alternative)
    AWS_REGION=us-east-1
    AWS_ACCESS_KEY_ID=AKIA...
    AWS_SECRET_ACCESS_KEY=secret
"""

from .abstract_provider import (
    AbstractSMSProvider,
    SMSMessage,
    SMSResponse,
    SMSProviderError,
    VerificationCodeExpiredError,
    InvalidVerificationCodeError,
    TooManyAttemptsError
)
from .sms_manager import SMSManager

# Provider implementations
try:
    from .twilio_provider import TwilioProvider, TwilioConfig
    __all__ = ["TwilioProvider", "TwilioConfig"]
except ImportError:
    pass

try:
    from .aws_sns_provider import AWSSNSProvider, AWSSNSConfig
    __all__ = __all__ + ["AWSSNSProvider", "AWSSNSConfig"]
except ImportError:
    pass

__all__ = [
    # Core classes
    "SMSManager",
    "AbstractSMSProvider",
    "SMSMessage",
    "SMSResponse",
    
    # Exceptions
    "SMSProviderError",
    "VerificationCodeExpiredError",
    "InvalidVerificationCodeError",
    "TooManyAttemptsError",
    
    # Providers (conditionally imported)
    *(__all__ if '__all__' in dir() else [])
]
