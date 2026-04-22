"""
Configuration module for Authy Package.

Provides a unified configuration model for all authentication components.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import os


@dataclass
class DatabaseConfig:
    """Database configuration."""
    db_type: str = "sql"  # "sql" or "mongodb"
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
class JWTConfig:
    """JWT token configuration."""
    secret_key: str = ""
    algorithm: str = "HS256"
    access_token_expiration: int = 3600  # 1 hour
    refresh_token_expiration: int = 604800  # 7 days
    
    def __post_init__(self):
        if not self.secret_key:
            self.secret_key = os.getenv("AUTHY_JWT_SECRET", "your-secret-key-change-in-production")


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
class SecurityConfig:
    """Security configuration."""
    password_hash_algorithm: str = "bcrypt"  # "bcrypt" or "argon2"
    rate_limit_enabled: bool = True
    rate_limit_max_attempts: int = 5
    rate_limit_window_seconds: int = 300  # 5 minutes
    account_lockout_duration: int = 900  # 15 minutes
    mfa_required: bool = False
    jwt_config: JWTConfig = field(default_factory=JWTConfig)


@dataclass
class EmailConfig:
    """Email configuration for password resets."""
    enabled: bool = False
    provider: str = "mailjet"  # "mailjet", "sendgrid", "ses", etc.
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    sender_email: Optional[str] = None
    sender_name: Optional[str] = None


@dataclass
class AuthConfig:
    """
    Main configuration class for Authy Package.
    
    Usage:
        config = AuthConfig(
            database=DatabaseConfig(db_type="sql", connection_string="sqlite+aiosqlite:///auth.db"),
            cache=CacheConfig(redis_url="redis://localhost:6379"),
            security=SecurityConfig(rate_limit_enabled=True),
            social=SocialAuthConfig(google_client_id="..."),
            cognito=CognitoConfig(enabled=False),
            email=EmailConfig(enabled=False)
        )
    """
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    social: SocialAuthConfig = field(default_factory=SocialAuthConfig)
    cognito: CognitoConfig = field(default_factory=CognitoConfig)
    email: EmailConfig = field(default_factory=EmailConfig)
    
    # Application settings
    app_name: str = "Authy App"
    debug: bool = False
    
    @classmethod
    def from_env(cls) -> 'AuthConfig':
        """Create configuration from environment variables."""
        return cls(
            database=DatabaseConfig(
                db_type=os.getenv("AUTHY_DB_TYPE", "sql"),
                connection_string=os.getenv("AUTHY_DB_URL", ""),
                db_name=os.getenv("AUTHY_DB_NAME"),
                collection_name=os.getenv("AUTHY_DB_COLLECTION"),
            ),
            cache=CacheConfig(
                enabled=os.getenv("AUTHY_CACHE_ENABLED", "true").lower() == "true",
                redis_url=os.getenv("AUTHY_REDIS_URL", "redis://localhost:6379"),
                token_expiration=int(os.getenv("AUTHY_TOKEN_EXPIRATION", "3600")),
                refresh_token_expiration=int(os.getenv("AUTHY_REFRESH_TOKEN_EXPIRATION", "604800")),
            ),
            security=SecurityConfig(
                jwt_config=JWTConfig(
                    secret_key=os.getenv("AUTHY_JWT_SECRET", ""),
                ),
                rate_limit_enabled=os.getenv("AUTHY_RATE_LIMIT_ENABLED", "true").lower() == "true",
                rate_limit_max_attempts=int(os.getenv("AUTHY_RATE_LIMIT_MAX_ATTEMPTS", "5")),
            ),
            social=SocialAuthConfig(
                google_client_id=os.getenv("GOOGLE_CLIENT_ID"),
                google_client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
                google_redirect_uri=os.getenv("GOOGLE_REDIRECT_URI"),
                facebook_app_id=os.getenv("FACEBOOK_APP_ID"),
                facebook_app_secret=os.getenv("FACEBOOK_APP_SECRET"),
                github_client_id=os.getenv("GITHUB_CLIENT_ID"),
                github_client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
                apple_client_id=os.getenv("APPLE_CLIENT_ID"),
                apple_team_id=os.getenv("APPLE_TEAM_ID"),
                apple_key_id=os.getenv("APPLE_KEY_ID"),
                apple_private_key=os.getenv("APPLE_PRIVATE_KEY"),
            ),
            cognito=CognitoConfig(
                enabled=os.getenv("AUTHY_COGNITO_ENABLED", "false").lower() == "true",
                region_name=os.getenv("AWS_REGION"),
                user_pool_id=os.getenv("COGNITO_USER_POOL_ID"),
                app_client_id=os.getenv("COGNITO_APP_CLIENT_ID"),
            ),
            email=EmailConfig(
                enabled=os.getenv("AUTHY_EMAIL_ENABLED", "false").lower() == "true",
                api_key=os.getenv("MAILJET_API_KEY"),
                api_secret=os.getenv("MAILJET_API_SECRET"),
                sender_email=os.getenv("SENDER_EMAIL"),
                sender_name=os.getenv("SENDER_NAME"),
            ),
        )
    
    def validate(self) -> bool:
        """Validate the configuration."""
        errors = []
        
        if not self.database.connection_string and self.database.db_type != "memory":
            errors.append("Database connection string is required")
        
        if self.cache.enabled and not self.cache.redis_url:
            errors.append("Redis URL is required when cache is enabled")
        
        if not self.security.jwt_config.secret_key or self.security.jwt_config.secret_key == "your-secret-key-change-in-production":
            errors.append("JWT secret key must be set and should not use the default value")
        
        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
        
        return True
