"""Tessera Package — authentication building blocks (CONTRACTS.md).

Import model (§0.9):

- Only the pure ``errors`` and ``config`` modules are imported eagerly.
- Every other submodule is probed with a guarded import at package init:
  success sets a ``*_AVAILABLE`` flag and adds the submodule's public
  names to ``__all__``; failure (missing optional dependency or a module
  mid-refactor) sets the flag to ``False`` and keeps the name out of
  ``__all__``. ``import tessera`` therefore succeeds with zero
  optional dependencies installed.
- A PEP 562 ``__getattr__`` lazily resolves exported names, raising an
  informative :class:`ImportError` when the owning submodule is
  unavailable.

``get_auth()`` / ``init_auth()`` ALWAYS call ``AuthConfig.validate()``
before returning an :class:`AuthManager`.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any, Dict, List, Optional, Tuple

__version__ = "2.0.0"
__author__ = "Tessera Team"

logger = logging.getLogger("tessera")

# Eager, dependency-free foundation imports.
from .config import AuthConfig
from . import errors as _errors  # noqa: F401

_auth_instance: Optional[Any] = None

#: name -> (submodule path relative to tessera, attribute name).
_LAZY_EXPORTS: Dict[str, Tuple[str, str]] = {
    # core
    "AuthManager": ("core.auth_manager", "TraditionalAuthManager"),
    "TraditionalAuthManager": ("core.auth_manager", "TraditionalAuthManager"),
    "CognitoAuthManager": ("core.auth_manager", "CognitoAuthManager"),
    "SocialAuthManager": ("core.auth_manager", "SocialAuthManager"),
    # sessions
    "SessionManager": ("sessions.session_manager", "SessionManager"),
    "Session": ("sessions.session_manager", "Session"),
    # mfa
    "MFAAuthManager": ("mfa.mfa_setup", "MFAAuthManager"),
    # passwordless
    "MagicLinkManager": ("passwordless.magic_link", "MagicLinkManager"),
    "PasskeyManager": ("passwordless.passkey", "PasskeyManager"),
    # password security
    "HibpProvider": ("password_security", "HibpProvider"),
    "HibpConfig": ("password_security", "HibpConfig"),
    "PasswordSecurityManager": ("password_security", "PasswordSecurityManager"),
    "PasswordPolicy": ("password_security", "PasswordPolicy"),
    # organizations / webhooks / admin / frameworks
    "OrganizationManager": ("organizations.org_manager", "OrganizationManager"),
    "WebhookManager": ("webhooks.webhook_manager", "WebhookManager"),
    "AuditLogger": ("admin.audit_logger", "AuditLogger"),
    "FastAPIAuth": ("frameworks.fastapi_adapter", "FastAPIAuth"),
    "FlaskAuth": ("frameworks.flask_adapter", "FlaskAuth"),
    "DjangoAuth": ("frameworks.django_adapter", "DjangoAuth"),
    # sms
    "SMSManager": ("sms", "SMSManager"),
    "AbstractSMSProvider": ("sms", "AbstractSMSProvider"),
    "SMSProviderError": ("sms", "SMSProviderError"),
    "VerificationCodeExpiredError": ("sms", "VerificationCodeExpiredError"),
    "InvalidVerificationCodeError": ("sms", "InvalidVerificationCodeError"),
    "TooManyAttemptsError": ("sms", "TooManyAttemptsError"),
    "TwilioProvider": ("sms.twilio_provider", "TwilioProvider"),
    "TwilioConfig": ("sms.twilio_provider", "TwilioConfig"),
    "AWSSNSProvider": ("sms.aws_sns_provider", "AWSSNSProvider"),
    "AWSSNSConfig": ("sms.aws_sns_provider", "AWSSNSConfig"),
    # bot protection
    "BotProtectionManager": ("bot_protection", "BotProtectionManager"),
    "AbstractCaptchaProvider": ("bot_protection", "AbstractCaptchaProvider"),
    "BotProtectionError": ("bot_protection", "BotProtectionError"),
    "RateLimitExceededError": ("bot_protection", "RateLimitExceededError"),
    "SuspiciousActivityError": ("bot_protection", "SuspiciousActivityError"),
    "RiskLevel": ("bot_protection", "RiskLevel"),
    "hCaptchaProvider": ("bot_protection.hcaptcha_provider", "hCaptchaProvider"),
    "hCaptchaConfig": ("bot_protection.hcaptcha_provider", "hCaptchaConfig"),
    "ReCaptchaProvider": ("bot_protection.recaptcha_provider", "ReCaptchaProvider"),
    "ReCaptchaConfig": ("bot_protection.recaptcha_provider", "ReCaptchaConfig"),
    # saml / oidc
    "SAMLManager": ("saml", "SAMLManager"),
    "SAMLConfig": ("saml", "SAMLConfig"),
    "OIDCManager": ("oidc", "OIDCManager"),
    "OIDCConfig": ("oidc", "OIDCConfig"),
    # social
    "AppleManager": ("social", "AppleManager"),
    "GitHubManager": ("social", "GitHubManager"),
    "FacebookManager": ("social", "FacebookManager"),
    "GoogleManager": ("social", "GoogleManager"),
    # migration / compliance
    "get_importer": ("migration", "get_importer"),
    "verify_and_upgrade_legacy_hash": ("migration", "verify_and_upgrade_legacy_hash"),
    "GDPRComplianceEngine": ("compliance", "GDPRComplianceEngine"),
    "SOC2AuditLogger": ("compliance", "SOC2AuditLogger"),
    "build_security_report": ("compliance", "build_security_report"),
    # foundation convenience re-exports
    "AbstractDatabase": ("db", "AbstractDatabase"),
    "InMemoryDatabase": ("db", "InMemoryDatabase"),
    "get_database": ("db", "get_database"),
    "AbstractCache": ("cache", "AbstractCache"),
    "InMemoryCache": ("cache", "InMemoryCache"),
    "RedisCache": ("cache", "RedisCache"),
    "JWTTokenManager": ("utils", "JWTTokenManager"),
    "SecurityManager": ("utils", "SecurityManager"),
    "AuthConfig": ("config", "AuthConfig"),
}

#: submodule probe unit for *_AVAILABLE flags: flag prefix -> module path.
_SUBMODULE_PROBES: Dict[str, str] = {
    "CORE": "core",
    "SESSIONS": "sessions",
    "MFA": "mfa",
    "PASSWORDLESS": "passwordless",
    "PASSWORD_SECURITY": "password_security",
    "ORGANIZATIONS": "organizations",
    "WEBHOOKS": "webhooks",
    "ADMIN": "admin",
    "FRAMEWORKS": "frameworks",
    "SMS": "sms",
    "BOT_PROTECTION": "bot_protection",
    "SAML": "saml",
    "OIDC": "oidc",
    "SOCIAL": "social",
    "MIGRATION": "migration",
    "COMPLIANCE": "compliance",
}

#: Populated below: e.g. CORE_AVAILABLE, SMS_AVAILABLE, ...
#: Plus ``AVAILABLE_MODULES`` for introspection.
AVAILABLE_MODULES: Dict[str, bool] = {}


def _probe_submodules() -> None:
    """Guarded import of every submodule; set *_AVAILABLE flags (§0.9)."""
    for flag_prefix, module_path in _SUBMODULE_PROBES.items():
        try:
            importlib.import_module(f".{module_path}", __name__)
            available = True
        except Exception as exc:  # noqa: BLE001 - any failure degrades gracefully
            available = False
            logger.debug("tessera.%s unavailable: %s", module_path, exc)
        AVAILABLE_MODULES[flag_prefix] = available
        globals()[f"{flag_prefix}_AVAILABLE"] = available


def _module_flag_for(export_module: str) -> str:
    """Map an export's module path back to its probe flag prefix."""
    top = export_module.split(".", 1)[0].upper()
    return top if top in _SUBMODULE_PROBES else "CORE"


def _build_all() -> List[str]:
    """__all__ only lists names whose owning submodule imported cleanly."""
    names: List[str] = ["AuthConfig", "get_auth", "init_auth", "__version__"]
    for name, (module_path, _attr) in _LAZY_EXPORTS.items():
        if name == "AuthConfig":
            continue
        if AVAILABLE_MODULES.get(_module_flag_for(module_path), False):
            names.append(name)
    return names


_probe_submodules()
__all__ = _build_all()


def __getattr__(name: str) -> Any:
    """PEP 562 lazy resolution of exported names."""
    if name in _LAZY_EXPORTS:
        module_path, attribute = _LAZY_EXPORTS[name]
        try:
            module = importlib.import_module(f".{module_path}", __name__)
        except Exception as exc:  # noqa: BLE001
            raise ImportError(
                f"tessera.{name} is unavailable: failed to import "
                f"tessera.{module_path}: {exc}"
            ) from exc
        try:
            value = getattr(module, attribute)
        except AttributeError as exc:
            raise ImportError(
                f"tessera.{name} is unavailable: "
                f"tessera.{module_path} has no attribute {attribute!r}"
            ) from exc
        globals()[name] = value  # cache for subsequent access
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> List[str]:
    return sorted(set(list(globals()) + __all__))


# ---------------------------------------------------------------------------
# global instance helpers
# ---------------------------------------------------------------------------

def _build_auth_stack(config: AuthConfig) -> Any:
    """Construct the default db/cache/manager stack for a validated config."""
    from .cache import RedisCache
    from .core.auth_manager import TraditionalAuthManager
    from .db import get_database
    from .utils.security import SecurityManager

    db = get_database(config.database)

    cache = None
    if config.cache.enabled:
        try:
            cache = RedisCache(config.cache.redis_url)
        except Exception as exc:  # noqa: BLE001 - degrade to cache-less mode
            logger.warning("Cache unavailable (%s); continuing without it", exc)
            cache = None

    security_manager = SecurityManager(db, cache, config) if cache is not None else None
    return TraditionalAuthManager(
        db,
        config,
        cache=cache,
        security_manager=security_manager,
    )


def get_auth(config: Optional[AuthConfig] = None) -> Any:
    """Get (or create) the global auth instance.

    With no config, settings are loaded from environment variables. The
    config is ALWAYS validated before an AuthManager is returned.

    Usage:
        from tessera import get_auth
        auth = get_auth()  # auto-loads from ENV
    """
    global _auth_instance
    if _auth_instance is None:
        if config is None:
            config = AuthConfig.from_env()
        config.validate()
        _auth_instance = _build_auth_stack(config)
    return _auth_instance


def init_auth(config: AuthConfig) -> Any:
    """Initialize the global auth instance with an explicit config.

    Usage:
        from tessera import init_auth, AuthConfig
        config = AuthConfig(jwt_secret="...", database=...)
        auth = init_auth(config)
    """
    global _auth_instance
    config.validate()
    _auth_instance = _build_auth_stack(config)
    return _auth_instance
