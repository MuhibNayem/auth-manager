# authy_package/__init__.py
"""
Authy Package - Enterprise-Grade Authentication for Python

Market-Leading Features:
- 🔐 Passwordless Auth (Magic Links, OTP, Passkeys/WebAuthn)
- 🏢 Multi-Tenancy & Organizations
- 🎯 Advanced Session Management
- 📡 Real-time Webhooks
- 🛡️ Fraud Detection & Anomaly Monitoring
- 🚀 One-Line Framework Integration
- 📊 Built-in Admin Dashboard API
- 🔄 Automatic Token Refresh
- 🌍 i18n Ready
- 📝 Audit Logging
- ⚡ Rate Limiting & Bot Protection
- 📱 Phone/SMS Authentication
- 🔒 Breached Password Detection

Unique Developer-Loving Features:
- 🪄 Magic Import: `from authy import auth` (auto-configured)
- 🧪 Mock Mode for Testing (no external deps)
- 📦 Embedded UI Kit URLs (pre-built components)
- 🔮 Predictive Session Pre-fetching
- 🎭 User Impersonation (debugging support)
- 🧩 Plugin System for Custom Providers
- 📈 Built-in Analytics Events
- 🛠️ CLI Tool for Scaffolding
"""

__version__ = "2.0.0"
__author__ = "Authy Team"

from .config import AuthConfig
# Core auth managers - using existing classes
from .core.auth_manager import TraditionalAuthManager as AuthManager
from .core.auth_manager import CognitoAuthManager, SocialAuthManager
from .sessions.session_manager import SessionManager
from .passwordless.magic_link import MagicLinkManager
from .passwordless.passkey import PasskeyManager
from .organizations.org_manager import OrganizationManager
from .webhooks.webhook_manager import WebhookManager
from .admin.audit_logger import AuditLogger
from .frameworks.fastapi_adapter import FastAPIAuth
from .frameworks.flask_adapter import FlaskAuth
from .frameworks.django_adapter import DjangoAuth

# Security modules - SMS
from .sms import (
    SMSManager,
    AbstractSMSProvider,
    SMSProviderError,
    VerificationCodeExpiredError,
    InvalidVerificationCodeError,
    TooManyAttemptsError
)

# Conditionally import providers
try:
    from .sms.twilio_provider import TwilioProvider, TwilioConfig
    __twilio_available = True
except ImportError:
    __twilio_available = False

try:
    from .sms.aws_sns_provider import AWSSNSProvider, AWSSNSConfig
    __sns_available = True
except ImportError:
    __sns_available = False

# Security modules - Bot Protection
from .bot_protection import (
    BotProtectionManager,
    AbstractCaptchaProvider,
    BotProtectionError,
    RateLimitExceededError,
    SuspiciousActivityError,
    RiskLevel
)

# Conditionally import CAPTCHA providers
try:
    from .bot_protection.hcaptcha_provider import hCaptchaProvider, hCaptchaConfig
    __hcaptcha_available = True
except ImportError:
    __hcaptcha_available = False

try:
    from .bot_protection.recaptcha_provider import ReCaptchaProvider, ReCaptchaConfig
    __recaptcha_available = True
except ImportError:
    __recaptcha_available = False

# Security modules - Password Security
from .password_security import HibpProvider, HibpConfig, PasswordSecurityManager, PasswordPolicy

__all__ = [
    # Core
    "AuthConfig",
    "AuthManager",
    "CognitoAuthManager",
    "SocialAuthManager",
    "SessionManager",
    "MagicLinkManager",
    "PasskeyManager",
    "OrganizationManager",
    "WebhookManager",
    "AuditLogger",
    "FastAPIAuth",
    "FlaskAuth",
    "DjangoAuth",
    
    # Security modules - SMS
    "SMSManager",
    "AbstractSMSProvider",
    "SMSProviderError",
    "VerificationCodeExpiredError",
    "InvalidVerificationCodeError",
    "TooManyAttemptsError",
    "TwilioProvider",
    "TwilioConfig",
    "AWSSNSProvider",
    "AWSSNSConfig",
    
    # Security modules - Bot Protection
    "BotProtectionManager",
    "AbstractCaptchaProvider",
    "BotProtectionError",
    "RateLimitExceededError",
    "SuspiciousActivityError",
    "RiskLevel",
    "hCaptchaProvider",
    "hCaptchaConfig",
    "ReCaptchaProvider",
    "ReCaptchaConfig",
    
    # Security modules - Password Security
    "HibpProvider",
    "HibpConfig",
    "PasswordSecurityManager",
    "PasswordPolicy",
]

# Convenience global instance (lazy loaded)
_auth_instance = None


def get_auth(config: AuthConfig = None) -> AuthManager:
    """
    Get or create global auth instance.
    If no config provided, loads from environment variables.
    
    Usage:
        from authy_package import get_auth
        auth = get_auth()  # Auto-loads from ENV
    """
    global _auth_instance
    if _auth_instance is None:
        if config is None:
            config = AuthConfig.from_env()
        _auth_instance = AuthManager(config)
    return _auth_instance


def init_auth(config: AuthConfig) -> AuthManager:
    """
    Initialize auth with explicit config.
    
    Usage:
        from authy_package import init_auth, AuthConfig
        config = AuthConfig(jwt_secret="secret", ...)
        auth = init_auth(config)
    """
    global _auth_instance
    _auth_instance = AuthManager(config)
    return _auth_instance
