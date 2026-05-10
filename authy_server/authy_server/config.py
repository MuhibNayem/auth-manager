"""
Authy Identity Server Configuration

Environment-based configuration for production deployments.
"""
import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    VERSION: str = "3.0.0"
    DEBUG: bool = os.getenv("AUTHY_DEBUG", "false").lower() == "true"
    WORKERS: int = int(os.getenv("AUTHY_WORKERS", "4"))
    BASE_URL: str = os.getenv("AUTHY_BASE_URL", "http://localhost:8000")
    
    # Security
    SECRET_KEY: Optional[str] = os.getenv("AUTHY_SECRET_KEY")
    JWT_ALGORITHM: str = "RS256"
    JWT_EXPIRY_SECONDS: int = int(os.getenv("AUTHY_JWT_EXPIRY", "3600"))
    REFRESH_TOKEN_EXPIRY_DAYS: int = int(os.getenv("AUTHY_REFRESH_EXPIRY", "30"))
    
    # Database
    DATABASE_URL: str = os.getenv("AUTHY_DATABASE_URL", "postgresql://authy:authy@localhost:5432/authy")
    DATABASE_POOL_SIZE: int = int(os.getenv("AUTHY_DB_POOL_SIZE", "10"))
    
    # Redis Cache
    REDIS_URL: str = os.getenv("AUTHY_REDIS_URL", "redis://localhost:6379/0")
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8080",
        os.getenv("AUTHY_ADMIN_URL", "http://localhost:3000"),
    ]
    
    # SAML
    SAML_CERTIFICATE_PATH: Optional[str] = os.getenv("AUTHY_SAML_CERT_PATH")
    SAML_PRIVATE_KEY_PATH: Optional[str] = os.getenv("AUTHY_SAML_KEY_PATH")
    
    # OIDC
    OIDC_ISSUER: str = os.getenv("AUTHY_OIDC_ISSUER", BASE_URL)
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("AUTHY_RATE_LIMIT", "100"))
    
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

    def model_post_init(self, __context) -> None:
        """Validate security-sensitive settings."""
        if self.SECRET_KEY:
            return
        if self.DEBUG:
            self.SECRET_KEY = "dev-secret-key-change-in-production"
            return
        raise ValueError("AUTHY_SECRET_KEY must be set when AUTHY_DEBUG is false")


settings = Settings()
