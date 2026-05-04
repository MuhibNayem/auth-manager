"""
Bot Protection Module for Authy Package.

Enterprise-grade, vendor-agnostic bot protection with support for multiple CAPTCHA providers,
rate limiting, and behavioral analysis.

Quick Start:
    from authy_package.bot_protection import BotProtectionManager, hCaptchaProvider
    
    # Initialize provider (uses environment variables)
    provider = hCaptchaProvider.from_env()
    
    # Create bot protection manager
    bot_manager = BotProtectionManager(
        provider=provider,
        cache=redis_cache,
        enable_rate_limiting=True,
        enable_behavioral_analysis=True
    )
    
    # Verify CAPTCHA token (e.g., from login form)
    is_human = await bot_manager.verify_captcha(
        token="captcha_token_from_frontend",
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0..."
    )
    
    # Check rate limit
    is_allowed = await bot_manager.check_rate_limit("login:user@example.com")

Environment Variables:
    # hCaptcha
    HCATCHA_SECRET_KEY=your_secret_key
    HCATCHA_SITE_KEY=your_site_key
    
    # reCAPTCHA (alternative)
    RECAPTCHA_SECRET_KEY=your_secret_key
    RECAPTCHA_SITE_KEY=your_site_key
"""

from .abstract_provider import (
    AbstractCaptchaProvider,
    CaptchaVerificationResult,
    BehavioralAnalysis,
    BotProtectionError,
    RateLimitExceededError,
    SuspiciousActivityError,
    RiskLevel
)
from .bot_protection_manager import BotProtectionManager

# Provider implementations
try:
    from .hcaptcha_provider import hCaptchaProvider, hCaptchaConfig
    __all__ = ["hCaptchaProvider", "hCaptchaConfig"]
except ImportError:
    pass

try:
    from .recaptcha_provider import ReCaptchaProvider, ReCaptchaConfig
    __all__ = __all__ + ["ReCaptchaProvider", "ReCaptchaConfig"] if '__all__' in dir() else ["ReCaptchaProvider", "ReCaptchaConfig"]
except ImportError:
    pass

__all__ = [
    # Core classes
    "BotProtectionManager",
    "AbstractCaptchaProvider",
    "CaptchaVerificationResult",
    
    # Exceptions
    "BotProtectionError",
    "RateLimitExceededError",
    "SuspiciousActivityError",
    
    # Providers (conditionally imported)
]

# Add providers if available
if 'hCaptchaProvider' in dir():
    __all__.extend(["hCaptchaProvider", "hCaptchaConfig"])
if 'ReCaptchaProvider' in dir():
    __all__.extend(["ReCaptchaProvider", "ReCaptchaConfig"])
