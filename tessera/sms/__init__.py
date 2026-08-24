"""SMS module for the Tessera package (CONTRACTS.md §0.9).

Vendor-agnostic SMS verification. The core API (manager + abstractions)
always imports; provider implementations are imported lazily/guarded so the
package works whether or not ``twilio``/``boto3`` are installed.

Quick start:
    from tessera.sms import SMSManager, TwilioProvider

    provider = TwilioProvider.from_env()
    manager = SMSManager(provider=provider, cache=cache)
    await manager.send_verification_code("+15551234567")
    result = await manager.verify_code("+15551234567", "123456")

Environment variables:
    TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_FROM_NUMBER  (Twilio)
    AWS_REGION / AWS_SNS_SENDER_ID (+ standard AWS credential chain)  (SNS)
"""

from .abstract_provider import (
    AbstractSMSProvider,
    InvalidVerificationCodeError,
    SMSMessage,
    SMSProviderError,
    SMSResponse,
    TooManyAttemptsError,
    VerificationCodeExpiredError,
)
from .sms_manager import SMSManager

__all__ = [
    # Core classes
    "SMSManager",
    "AbstractSMSProvider",
    "SMSMessage",
    "SMSResponse",
    # Exceptions (typed subclasses of tessera.errors, §1)
    "SMSProviderError",
    "VerificationCodeExpiredError",
    "InvalidVerificationCodeError",
    "TooManyAttemptsError",
]

# Provider availability flags (§0.9 lazy/guarded imports). Each block is
# independent so ANY combination of missing SDKs imports cleanly — including
# twilio absent while boto3 is present (the historical NameError path).
# The flags reflect the underlying SDK availability reported by the provider
# modules themselves (they import cleanly even without their SDK and raise
# informative ImportErrors at construction time).
TWILIO_AVAILABLE = False
try:
    from .twilio_provider import TWILIO_AVAILABLE as _TWILIO_SDK
    from .twilio_provider import TwilioConfig, TwilioProvider
except ImportError:
    pass
else:
    TWILIO_AVAILABLE = bool(_TWILIO_SDK)
    if TWILIO_AVAILABLE:
        __all__ += ["TwilioProvider", "TwilioConfig"]

AWS_SNS_AVAILABLE = False
try:
    from .aws_sns_provider import AWSSNSConfig, AWSSNSProvider
    from .aws_sns_provider import BOTO3_AVAILABLE as _BOTO3_SDK
except ImportError:
    pass
else:
    AWS_SNS_AVAILABLE = bool(_BOTO3_SDK)
    if AWS_SNS_AVAILABLE:
        __all__ += ["AWSSNSProvider", "AWSSNSConfig"]
