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
from .core.auth_manager import AuthManager
from .sessions.session_manager import SessionManager
from .passwordless.magic_link import MagicLinkManager
from .passwordless.passkey import PasskeyManager
from .organizations.org_manager import OrganizationManager
from .webhooks.webhook_manager import WebhookManager
from .admin.audit_logger import AuditLogger
from .frameworks.fastapi_adapter import FastAPIAuth
from .frameworks.flask_adapter import FlaskAuth
from .frameworks.django_adapter import DjangoAuth

__all__ = [
    "AuthConfig",
    "AuthManager",
    "SessionManager",
    "MagicLinkManager",
    "PasskeyManager",
    "OrganizationManager",
    "WebhookManager",
    "AuditLogger",
    "FastAPIAuth",
    "FlaskAuth",
    "DjangoAuth",
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
