"""Configuration model for the Authy package.

Canonical attribute contract per docs/CONTRACTS.md §2. The style is a
dataclass tree: flat canonical fields on :class:`AuthConfig` plus retained
nested configs (database, cache, social, cognito, sms, bot_protection,
password_security). :meth:`AuthConfig.from_env` reads ``AUTHY_*`` environment
variables (names preserved from the legacy implementation); new fields add
new ``AUTHY_*`` variables following the same convention.

There is intentionally NO hardcoded default JWT secret: ``jwt_secret``
defaults to ``None`` and :meth:`AuthConfig.validate` fails loudly.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, List, Optional

from authy_package.errors import ConfigError

logger = logging.getLogger("authy.config")

#: Environments accepted by ``AuthConfig.env``.
VALID_ENVIRONMENTS = ("development", "staging", "production")

#: Password hashing algorithms accepted by ``password_hash_algorithm``.
VALID_HASH_ALGORITHMS = ("bcrypt", "argon2")

#: db_type values accepted by the database factory.
VALID_DB_TYPES = ("sql", "mongodb", "dynamodb", "memory")

#: The publicly documented default secret that shipped in older versions of
#: this package. It must never validate as a real secret.
PUBLIC_DEFAULT_JWT_SECRET = "your-secret-key-change-in-production"

#: Long characteristic placeholder phrases. Substring matching is safe for
#: these: collision with a high-entropy random secret is astronomically
#: unlikely, and they catch the classic documentation placeholders.
_PLACEHOLDER_PHRASES = (
    "placeholder",
    "changeme",
    "change_me",
    "change-in-production",
    "your-secret",
    "your_secret",
    "your-super-secret",
    "your-password",
)

#: Short markers are placeholders only when they appear as a DELIMITED token
#: (e.g. "abc-xxx-def"), so high-entropy random secrets such as
#: ``secrets.token_urlsafe`` output are never false-positived.
_PLACEHOLDER_TOKENS = ("xxx", "example", "dummy")

_PLACEHOLDER_SPLIT_RE = re.compile(r"[^a-z0-9]+")


# ---------------------------------------------------------------------------
# env parsing helpers
# ---------------------------------------------------------------------------

def _env_str(name: str, default: Optional[str] = None) -> Optional[str]:
    """Read a string env var; empty values are treated as unset."""
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value


def _env_int(name: str, default: int) -> int:
    """Read an integer env var, raising ConfigError on malformed values."""
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"Environment variable {name} must be an integer, got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean env var ('true'/'1'/'yes' vs anything else)."""
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("true", "1", "yes", "on")


def _env_float(name: str, default: float) -> float:
    """Read a float env var, raising ConfigError on malformed values."""
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"Environment variable {name} must be a number, got {raw!r}") from exc


def _contains_placeholder(value: Optional[str]) -> bool:
    """Return True when a secret/URL still contains a placeholder marker.

    Long characteristic phrases match as substrings; short markers
    ("xxx", "example", "dummy") must appear as delimited tokens so
    high-entropy random secrets never false-positive (review NEW-1).
    """
    if not value:
        return False
    lowered = value.lower()
    if any(phrase in lowered for phrase in _PLACEHOLDER_PHRASES):
        return True
    tokens = _PLACEHOLDER_SPLIT_RE.split(lowered)
    return any(token in _PLACEHOLDER_TOKENS for token in tokens)


# ---------------------------------------------------------------------------
# nested configs (retained dataclass tree)
# ---------------------------------------------------------------------------

@dataclass
class DatabaseConfig:
    """Database configuration."""

    db_type: str = "sql"  # "sql" | "mongodb" | "dynamodb" | "memory"
    connection_string: str = ""
    db_name: Optional[str] = None
    collection_name: Optional[str] = None
    orm_model: Optional[Any] = None


@dataclass
class CacheConfig:
    """Cache/Redis configuration."""

    enabled: bool = True
    redis_url: str = "redis://localhost:6379"
    token_expiration: int = 3600  # 1 hour
    refresh_token_expiration: int = 604800  # 7 days
    id_token_expiration: int = 3600


@dataclass
class SocialAuthConfig:
    """Social authentication provider configuration."""

    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None
    google_redirect_uri: Optional[str] = None

    facebook_app_id: Optional[str] = None
    facebook_app_secret: Optional[str] = None
    facebook_redirect_uri: Optional[str] = None

    github_client_id: Optional[str] = None
    github_client_secret: Optional[str] = None
    github_redirect_uri: Optional[str] = None

    apple_client_id: Optional[str] = None
    apple_team_id: Optional[str] = None
    apple_key_id: Optional[str] = None
    apple_private_key: Optional[str] = None
    apple_redirect_uri: Optional[str] = None


@dataclass
class CognitoConfig:
    """AWS Cognito configuration."""

    enabled: bool = False
    region_name: Optional[str] = None
    user_pool_id: Optional[str] = None
    app_client_id: Optional[str] = None


@dataclass
class SMSConfig:
    """SMS/Phone authentication configuration."""

    enabled: bool = False
    provider: str = "twilio"  # "twilio", "aws_sns", "vonage", etc.

    # Twilio settings
    twilio_account_sid: Optional[str] = None
    twilio_auth_token: Optional[str] = None
    twilio_from_number: Optional[str] = None
    twilio_messaging_service_sid: Optional[str] = None

    # AWS SNS settings
    aws_region: Optional[str] = None
    aws_sender_id: Optional[str] = None

    # Verification code settings
    code_length: int = 6
    expiration_seconds: int = 300
    max_attempts: int = 3
    rate_limit_window_seconds: int = 60
    max_sends_per_window: int = 3


@dataclass
class BotProtectionConfig:
    """Bot protection configuration."""

    enabled: bool = True
    provider: str = "hcaptcha"  # "hcaptcha", "recaptcha"

    # hCaptcha settings
    hcaptcha_secret_key: Optional[str] = None
    hcaptcha_site_key: Optional[str] = None

    # reCAPTCHA settings
    recaptcha_secret_key: Optional[str] = None
    recaptcha_site_key: Optional[str] = None
    recaptcha_version: str = "v3"
    recaptcha_min_score: float = 0.5

    # Rate limiting
    enable_rate_limiting: bool = True
    max_requests_per_minute: int = 10
    max_requests_per_hour: int = 100

    # Behavioral analysis
    enable_behavioral_analysis: bool = True

    # Actions that always require CAPTCHA
    captcha_required_actions: List[str] = field(
        default_factory=lambda: ["login", "register", "password_reset"]
    )


@dataclass
class PasswordSecurityConfig:
    """Password security policy configuration."""

    check_breached: bool = True
    hibp_api_key: Optional[str] = None

    # Password policy
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special_chars: bool = True
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?/"

    disallow_common_passwords: bool = True
    disallow_sequential_chars: bool = True
    disallow_repeated_chars: bool = True
    max_repeated_chars: int = 3
    disallow_username_in_password: bool = True


# ---------------------------------------------------------------------------
# main config
# ---------------------------------------------------------------------------

@dataclass
class AuthConfig:
    """Main configuration for the Authy package (CONTRACTS.md §2).

    Flat canonical fields live directly on this dataclass; nested configs are
    retained for database, cache, social, cognito, sms, bot_protection and
    password_security. ``jwt_secret`` defaults to ``None`` — callers MUST set
    it explicitly and call :meth:`validate` before use.
    """

    # core
    env: str = "development"  # "development" | "staging" | "production"

    # jwt
    jwt_secret: Optional[str] = None
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = 3600
    refresh_token_ttl_days: int = 7
    jwt_issuer: Optional[str] = None
    jwt_audience: Optional[str] = None
    jwt_clock_skew_seconds: int = 30

    # sessions
    session_expiry_seconds: int = 86400 * 7
    max_concurrent_sessions: int = 5
    revoke_sessions_on_password_change: bool = True

    # security
    rate_limit_enabled: bool = True
    rate_limit_max_attempts: int = 5
    rate_limit_window_seconds: int = 300
    account_lockout_duration_seconds: int = 900
    mfa_required: bool = False
    password_hash_algorithm: str = "bcrypt"  # "bcrypt" | "argon2"
    bcrypt_rounds: int = 12
    reset_token_ttl_seconds: int = 900
    base_url: str = "http://localhost:8000"

    # passwordless
    magic_link_ttl_seconds: int = 600
    default_redirect_url: Optional[str] = None
    auto_create_users: bool = False
    rp_id: Optional[str] = None
    rp_name: str = "Authy"

    # email (flat; keys per provider)
    email_enabled: bool = False
    email_provider: str = "mailjet"  # "mailjet" | "sendgrid" | "ses"
    mailjet_api_key: Optional[str] = None
    mailjet_api_secret: Optional[str] = None
    sendgrid_api_key: Optional[str] = None
    ses_access_key_id: Optional[str] = None
    ses_secret_access_key: Optional[str] = None
    ses_region: Optional[str] = None
    sender_email: Optional[str] = None
    sender_name: Optional[str] = None

    # application settings (retained)
    app_name: str = "Authy App"
    debug: bool = False

    # nested configs (retained dataclass tree)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    social: SocialAuthConfig = field(default_factory=SocialAuthConfig)
    cognito: CognitoConfig = field(default_factory=CognitoConfig)
    sms: SMSConfig = field(default_factory=SMSConfig)
    bot_protection: BotProtectionConfig = field(default_factory=BotProtectionConfig)
    password_security: PasswordSecurityConfig = field(default_factory=PasswordSecurityConfig)

    @property
    def is_production(self) -> bool:
        """True when running in the production environment."""
        return self.env == "production"

    @property
    def refresh_token_ttl_seconds(self) -> int:
        """Refresh token lifetime expressed in seconds."""
        return self.refresh_token_ttl_days * 86400

    @classmethod
    def from_env(cls) -> "AuthConfig":
        """Create configuration from environment variables.

        Legacy ``AUTHY_*`` variable names are preserved; new canonical fields
        add ``AUTHY_*`` variables following the same convention.
        """
        return cls(
            env=_env_str("AUTHY_ENV", "development") or "development",
            jwt_secret=_env_str("AUTHY_JWT_SECRET"),
            jwt_algorithm=_env_str("AUTHY_JWT_ALGORITHM", "HS256") or "HS256",
            access_token_ttl_seconds=_env_int("AUTHY_TOKEN_EXPIRATION", 3600),
            refresh_token_ttl_days=_env_int("AUTHY_REFRESH_TOKEN_TTL_DAYS", 7),
            jwt_issuer=_env_str("AUTHY_JWT_ISSUER"),
            jwt_audience=_env_str("AUTHY_JWT_AUDIENCE"),
            jwt_clock_skew_seconds=_env_int("AUTHY_JWT_CLOCK_SKEW_SECONDS", 30),
            session_expiry_seconds=_env_int("AUTHY_SESSION_EXPIRY_SECONDS", 86400 * 7),
            max_concurrent_sessions=_env_int("AUTHY_MAX_CONCURRENT_SESSIONS", 5),
            revoke_sessions_on_password_change=_env_bool(
                "AUTHY_REVOKE_SESSIONS_ON_PASSWORD_CHANGE", True
            ),
            rate_limit_enabled=_env_bool("AUTHY_RATE_LIMIT_ENABLED", True),
            rate_limit_max_attempts=_env_int("AUTHY_RATE_LIMIT_MAX_ATTEMPTS", 5),
            rate_limit_window_seconds=_env_int("AUTHY_RATE_LIMIT_WINDOW_SECONDS", 300),
            account_lockout_duration_seconds=_env_int(
                "AUTHY_ACCOUNT_LOCKOUT_DURATION_SECONDS", 900
            ),
            mfa_required=_env_bool("AUTHY_MFA_REQUIRED", False),
            password_hash_algorithm=_env_str("AUTHY_PASSWORD_HASH_ALGORITHM", "bcrypt") or "bcrypt",
            bcrypt_rounds=_env_int("AUTHY_BCRYPT_ROUNDS", 12),
            reset_token_ttl_seconds=_env_int("AUTHY_RESET_TOKEN_TTL_SECONDS", 900),
            base_url=_env_str("AUTHY_BASE_URL", "http://localhost:8000") or "http://localhost:8000",
            magic_link_ttl_seconds=_env_int("AUTHY_MAGIC_LINK_TTL_SECONDS", 600),
            default_redirect_url=_env_str("AUTHY_DEFAULT_REDIRECT_URL"),
            auto_create_users=_env_bool("AUTHY_AUTO_CREATE_USERS", False),
            rp_id=_env_str("AUTHY_RP_ID"),
            rp_name=_env_str("AUTHY_RP_NAME", "Authy") or "Authy",
            email_enabled=_env_bool("AUTHY_EMAIL_ENABLED", False),
            email_provider=_env_str("AUTHY_EMAIL_PROVIDER", "mailjet") or "mailjet",
            mailjet_api_key=_env_str("MAILJET_API_KEY"),
            mailjet_api_secret=_env_str("MAILJET_API_SECRET"),
            sendgrid_api_key=_env_str("SENDGRID_API_KEY"),
            ses_access_key_id=_env_str("SES_ACCESS_KEY_ID"),
            ses_secret_access_key=_env_str("SES_SECRET_ACCESS_KEY"),
            ses_region=_env_str("SES_REGION"),
            sender_email=_env_str("SENDER_EMAIL"),
            sender_name=_env_str("SENDER_NAME"),
            database=DatabaseConfig(
                db_type=_env_str("AUTHY_DB_TYPE", "sql") or "sql",
                connection_string=_env_str("AUTHY_DB_URL", "") or "",
                db_name=_env_str("AUTHY_DB_NAME"),
                collection_name=_env_str("AUTHY_DB_COLLECTION"),
            ),
            cache=CacheConfig(
                enabled=_env_bool("AUTHY_CACHE_ENABLED", True),
                redis_url=_env_str("AUTHY_REDIS_URL", "redis://localhost:6379")
                or "redis://localhost:6379",
                token_expiration=_env_int("AUTHY_TOKEN_EXPIRATION", 3600),
                refresh_token_expiration=_env_int("AUTHY_REFRESH_TOKEN_EXPIRATION", 604800),
            ),
            social=SocialAuthConfig(
                google_client_id=_env_str("GOOGLE_CLIENT_ID"),
                google_client_secret=_env_str("GOOGLE_CLIENT_SECRET"),
                google_redirect_uri=_env_str("GOOGLE_REDIRECT_URI"),
                facebook_app_id=_env_str("FACEBOOK_APP_ID"),
                facebook_app_secret=_env_str("FACEBOOK_APP_SECRET"),
                facebook_redirect_uri=_env_str("FACEBOOK_REDIRECT_URI"),
                github_client_id=_env_str("GITHUB_CLIENT_ID"),
                github_client_secret=_env_str("GITHUB_CLIENT_SECRET"),
                github_redirect_uri=_env_str("GITHUB_REDIRECT_URI"),
                apple_client_id=_env_str("APPLE_CLIENT_ID"),
                apple_team_id=_env_str("APPLE_TEAM_ID"),
                apple_key_id=_env_str("APPLE_KEY_ID"),
                apple_private_key=_env_str("APPLE_PRIVATE_KEY"),
                apple_redirect_uri=_env_str("APPLE_REDIRECT_URI"),
            ),
            cognito=CognitoConfig(
                enabled=_env_bool("AUTHY_COGNITO_ENABLED", False),
                region_name=_env_str("AWS_REGION"),
                user_pool_id=_env_str("COGNITO_USER_POOL_ID"),
                app_client_id=_env_str("COGNITO_APP_CLIENT_ID"),
            ),
            sms=SMSConfig(
                enabled=_env_bool("AUTHY_SMS_ENABLED", False),
                provider=_env_str("AUTHY_SMS_PROVIDER", "twilio") or "twilio",
                twilio_account_sid=_env_str("TWILIO_ACCOUNT_SID"),
                twilio_auth_token=_env_str("TWILIO_AUTH_TOKEN"),
                twilio_from_number=_env_str("TWILIO_FROM_NUMBER"),
                twilio_messaging_service_sid=_env_str("TWILIO_MESSAGING_SERVICE_SID"),
                aws_region=_env_str("AWS_REGION"),
                aws_sender_id=_env_str("AWS_SNS_SENDER_ID"),
                code_length=_env_int("AUTHY_SMS_CODE_LENGTH", 6),
                expiration_seconds=_env_int("AUTHY_SMS_CODE_EXPIRATION", 300),
                max_attempts=_env_int("AUTHY_SMS_MAX_ATTEMPTS", 3),
            ),
            bot_protection=BotProtectionConfig(
                enabled=_env_bool("AUTHY_BOT_PROTECTION_ENABLED", True),
                provider=_env_str("AUTHY_CAPTCHA_PROVIDER", "hcaptcha") or "hcaptcha",
                hcaptcha_secret_key=_env_str("HCAPTCHA_SECRET_KEY"),
                hcaptcha_site_key=_env_str("HCAPTCHA_SITE_KEY"),
                recaptcha_secret_key=_env_str("RECAPTCHA_SECRET_KEY"),
                recaptcha_site_key=_env_str("RECAPTCHA_SITE_KEY"),
                recaptcha_version=_env_str("RECAPTCHA_VERSION", "v3") or "v3",
                recaptcha_min_score=_env_float("RECAPTCHA_MIN_SCORE", 0.5),
                enable_rate_limiting=_env_bool("AUTHY_RATE_LIMIT_ENABLED", True),
                max_requests_per_minute=_env_int("AUTHY_MAX_REQUESTS_PER_MINUTE", 10),
                max_requests_per_hour=_env_int("AUTHY_MAX_REQUESTS_PER_HOUR", 100),
            ),
            password_security=PasswordSecurityConfig(
                check_breached=_env_bool("AUTHY_CHECK_BREACHED_PASSWORDS", True),
                hibp_api_key=_env_str("HIBP_API_KEY"),
                min_length=_env_int("AUTHY_PASSWORD_MIN_LENGTH", 12),
                require_uppercase=_env_bool("AUTHY_PASSWORD_REQUIRE_UPPERCASE", True),
                require_lowercase=_env_bool("AUTHY_PASSWORD_REQUIRE_LOWERCASE", True),
                require_numbers=_env_bool("AUTHY_PASSWORD_REQUIRE_NUMBERS", True),
                require_special_chars=_env_bool("AUTHY_PASSWORD_REQUIRE_SPECIAL_CHARS", True),
                disallow_common_passwords=_env_bool("AUTHY_PASSWORD_DISALLOW_COMMON", True),
                disallow_sequential_chars=_env_bool("AUTHY_PASSWORD_DISALLOW_SEQUENTIAL", True),
                disallow_repeated_chars=_env_bool("AUTHY_PASSWORD_DISALLOW_REPEATED", True),
                max_repeated_chars=_env_int("AUTHY_PASSWORD_MAX_REPEATED", 3),
                disallow_username_in_password=_env_bool("AUTHY_PASSWORD_DISALLOW_USERNAME", True),
            ),
        )

    # ------------------------------------------------------------------
    # validation
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        """Validate the configuration, raising :class:`ConfigError` on failure.

        Raises when:
        - ``jwt_secret`` is None/empty or equals the public default string;
        - ``env == "production"`` and placeholder values remain (secrets,
          ``example.com`` URLs);
        - the database URL is missing for non-memory backends;
        - ``base_url`` is not HTTPS in production.

        Returns ``True`` when the configuration is valid.
        """
        errors: list[str] = []

        if self.env not in VALID_ENVIRONMENTS:
            errors.append(
                f"env must be one of {VALID_ENVIRONMENTS}, got {self.env!r}"
            )

        # JWT secret: never None/empty, never the public default.
        if not self.jwt_secret:
            errors.append(
                "jwt_secret must be set (env AUTHY_JWT_SECRET); there is no default"
            )
        elif self.jwt_secret == PUBLIC_DEFAULT_JWT_SECRET:
            errors.append(
                "jwt_secret must not be the public default string "
                f"{PUBLIC_DEFAULT_JWT_SECRET!r}"
            )
        elif _contains_placeholder(self.jwt_secret):
            errors.append("jwt_secret looks like a placeholder value")

        if self.password_hash_algorithm not in VALID_HASH_ALGORITHMS:
            errors.append(
                f"password_hash_algorithm must be one of {VALID_HASH_ALGORITHMS}, "
                f"got {self.password_hash_algorithm!r}"
            )
        if not 4 <= self.bcrypt_rounds <= 31:
            errors.append(f"bcrypt_rounds must be within 4..31, got {self.bcrypt_rounds}")

        for name in (
            "access_token_ttl_seconds",
            "refresh_token_ttl_days",
            "session_expiry_seconds",
            "rate_limit_window_seconds",
            "account_lockout_duration_seconds",
            "reset_token_ttl_seconds",
            "magic_link_ttl_seconds",
            "jwt_clock_skew_seconds",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or value <= 0:
                errors.append(f"{name} must be a positive integer, got {value!r}")
        if self.max_concurrent_sessions <= 0:
            errors.append(
                f"max_concurrent_sessions must be positive, got {self.max_concurrent_sessions}"
            )

        # Database.
        if self.database.db_type not in VALID_DB_TYPES:
            errors.append(
                f"database.db_type must be one of {VALID_DB_TYPES}, "
                f"got {self.database.db_type!r}"
            )
        elif self.database.db_type != "memory" and not self.database.connection_string:
            errors.append(
                f"database.connection_string is required for db_type "
                f"{self.database.db_type!r} (env AUTHY_DB_URL)"
            )

        # Cache.
        if self.cache.enabled and not self.cache.redis_url:
            errors.append("cache.redis_url is required when cache is enabled")

        # base_url must be an http(s) URL; HTTPS enforced in production (§6).
        if not self.base_url.startswith(("http://", "https://")):
            errors.append(f"base_url must start with http:// or https://, got {self.base_url!r}")
        if self.env == "production" and self.base_url.startswith("http://"):
            errors.append("base_url must use https:// in production")

        # Production placeholder sweep.
        if self.env == "production":
            for secret_name in (
                "mailjet_api_key",
                "mailjet_api_secret",
                "sendgrid_api_key",
                "ses_access_key_id",
                "ses_secret_access_key",
            ):
                if _contains_placeholder(getattr(self, secret_name)):
                    errors.append(f"{secret_name} looks like a placeholder value")
            for url_name in ("base_url", "default_redirect_url"):
                url_value = getattr(self, url_name)
                if url_value and "example.com" in url_value.lower():
                    errors.append(f"{url_name} still points at example.com")
            if self.sender_email and "example.com" in self.sender_email.lower():
                errors.append("sender_email still uses an example.com address")

        if errors:
            raise ConfigError("Configuration validation failed: " + "; ".join(errors))
        return True
