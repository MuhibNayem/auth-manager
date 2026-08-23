"""Fixtures for the core-area test suite (CONTRACTS.md §0.10).

Everything runs against InMemoryDatabase + InMemoryCache; no network.
"""

from __future__ import annotations

import os
import secrets
from typing import Any

import pytest

from authy_package.cache import InMemoryCache
from authy_package.config import AuthConfig, CacheConfig, DatabaseConfig
from authy_package.core.auth_manager import SocialAuthManager, TraditionalAuthManager
from authy_package.db import InMemoryDatabase
from authy_package.mfa.mfa_setup import MFAAuthManager
from authy_package.sessions.session_manager import SessionManager
from authy_package.utils.security import JWTTokenManager, SecurityManager

_ENV_PREFIXES = (
    "AUTHY_",
    "MAILJET_",
    "SENDGRID_",
    "SES_",
    "SENDER_",
    "GOOGLE_",
    "FACEBOOK_",
    "GITHUB_",
    "APPLE_",
    "TWILIO_",
    "HCAPTCHA_",
    "RECAPTCHA_",
    "COGNITO_",
    "HIBP_",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith(_ENV_PREFIXES):
            monkeypatch.delenv(name, raising=False)


def _make_config(**overrides: Any) -> AuthConfig:
    """Valid development config backed by the memory database."""
    kwargs: dict = dict(
        env="development",
        jwt_secret=secrets.token_urlsafe(32),
        bcrypt_rounds=4,  # test speed; validate() accepts 4..31
        database=DatabaseConfig(db_type="memory"),
        cache=CacheConfig(enabled=False),
        base_url="http://localhost:8000",
        rate_limit_max_attempts=5,
        rate_limit_window_seconds=300,
        account_lockout_duration_seconds=900,
    )
    kwargs.update(overrides)
    return AuthConfig(**kwargs)


@pytest.fixture
def make_config():
    return _make_config


@pytest.fixture
def config() -> AuthConfig:
    cfg = _make_config()
    assert cfg.validate() is True
    return cfg


@pytest.fixture
def cache() -> InMemoryCache:
    return InMemoryCache()


@pytest.fixture
async def db() -> InMemoryDatabase:
    database = InMemoryDatabase()
    await database.connect()
    return database


@pytest.fixture
def token_manager(config: AuthConfig) -> JWTTokenManager:
    return JWTTokenManager(config)


@pytest.fixture
def session_manager(
    config: AuthConfig, db: InMemoryDatabase, cache: InMemoryCache
) -> SessionManager:
    return SessionManager(config, db, cache)


@pytest.fixture
def mfa_manager(
    db: InMemoryDatabase, cache: InMemoryCache, config: AuthConfig
) -> MFAAuthManager:
    return MFAAuthManager(db, cache, config)


@pytest.fixture
def security_manager(
    db: InMemoryDatabase, cache: InMemoryCache, config: AuthConfig
) -> SecurityManager:
    return SecurityManager(db, cache, config)


@pytest.fixture
def auth(
    db: InMemoryDatabase,
    cache: InMemoryCache,
    config: AuthConfig,
    mfa_manager: MFAAuthManager,
    security_manager: SecurityManager,
    session_manager: SessionManager,
) -> TraditionalAuthManager:
    return TraditionalAuthManager(
        db,
        config,
        cache=cache,
        mfa_manager=mfa_manager,
        security_manager=security_manager,
        session_manager=session_manager,
    )


@pytest.fixture
def social(
    db: InMemoryDatabase,
    cache: InMemoryCache,
    config: AuthConfig,
    session_manager: SessionManager,
) -> SocialAuthManager:
    return SocialAuthManager(
        db, config, cache=cache, session_manager=session_manager
    )


@pytest.fixture
async def registered_user(auth: TraditionalAuthManager) -> dict:
    """A registered user record (via the public register API)."""
    result = await auth.register_user(
        username="alice",
        email="alice@example.com",
        password="Str0ng!Passw0rd#2024",
    )
    return result["user"]
