"""Bot protection module for the Authy package (CONTRACTS.md §0.9).

CAPTCHA verification, rate limiting and behavioral analysis. The core API
(manager + abstractions) always imports; CAPTCHA provider implementations
are imported lazily/guarded so the package works whether or not ``httpx``
is installed.

Quick start:
    from authy_package.bot_protection import BotProtectionManager, hCaptchaProvider

    provider = hCaptchaProvider.from_env()
    manager = BotProtectionManager(provider=provider, cache=cache)
    result = await manager.verify_captcha(token=token, ip_address=ip)

Environment variables:
    HCAPTCHA_SECRET_KEY / HCAPTCHA_SITE_KEY        (hCaptcha)
    RECAPTCHA_SECRET_KEY / RECAPTCHA_SITE_KEY      (reCAPTCHA)
"""

from .abstract_provider import (
    AbstractCaptchaProvider,
    BehavioralAnalysis,
    BotProtectionError,
    CaptchaVerificationResult,
    RateLimitExceededError,
    RiskLevel,
    SuspiciousActivityError,
)
from .bot_protection_manager import BotProtectionManager

__all__ = [
    # Core classes
    "BotProtectionManager",
    "AbstractCaptchaProvider",
    "CaptchaVerificationResult",
    "BehavioralAnalysis",
    "RiskLevel",
    # Exceptions
    "BotProtectionError",
    "RateLimitExceededError",
    "SuspiciousActivityError",
]

# Provider availability flags (§0.9). Each block is independent so ANY
# combination of missing optional deps imports cleanly.
HCAPTCHA_AVAILABLE = False
try:
    from .hcaptcha_provider import HTTPX_AVAILABLE as _HC_HTTPX
    from .hcaptcha_provider import hCaptchaConfig, hCaptchaProvider
except ImportError:
    pass
else:
    HCAPTCHA_AVAILABLE = bool(_HC_HTTPX)
    if HCAPTCHA_AVAILABLE:
        __all__ += ["hCaptchaProvider", "hCaptchaConfig"]

RECAPTCHA_AVAILABLE = False
try:
    from .recaptcha_provider import HTTPX_AVAILABLE as _RC_HTTPX
    from .recaptcha_provider import ReCaptchaConfig, ReCaptchaProvider
except ImportError:
    pass
else:
    RECAPTCHA_AVAILABLE = bool(_RC_HTTPX)
    if RECAPTCHA_AVAILABLE:
        __all__ += ["ReCaptchaProvider", "ReCaptchaConfig"]
