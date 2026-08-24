"""Shared fixtures for the foundation test suite (CONTRACTS.md §1-§6).

Everything runs against the in-memory fakes; no network or external services
are required (§0.10).
"""

from __future__ import annotations

import os
import secrets
from typing import Any

import pytest

from tessera.cache import InMemoryCache
from tessera.config import AuthConfig, CacheConfig, DatabaseConfig
from tessera.db import InMemoryDatabase
from tessera.utils.security import JWTTokenManager, SecurityManager

#: Env var prefixes cleared between tests so from_env() is deterministic.
_ENV_PREFIXES = (
    "TESSERA_",
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
_ENV_EXACT = ("AWS_REGION",)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip provider/config env vars so tests never leak into each other."""
    for name in list(os.environ):
        if name.startswith(_ENV_PREFIXES) or name in _ENV_EXACT:
            monkeypatch.delenv(name, raising=False)


def _make_config(**overrides: Any) -> AuthConfig:
    """Build a valid development AuthConfig backed by the memory database.

    bcrypt_rounds is lowered to 4 purely for test speed; validate() accepts
    4..31.
    """
    kwargs: dict[str, Any] = dict(
        env="development",
        # token_hex(32) is provably marker-safe: every placeholder marker in
        # AuthConfig.validate() contains a non-hex character, so a pure
        # [0-9a-f] secret can never be flagged as a placeholder (token_urlsafe
        # could rarely emit e.g. 'xxx', flaking validate()). 256-bit entropy.
        jwt_secret=secrets.token_hex(32),
        bcrypt_rounds=4,
        database=DatabaseConfig(db_type="memory"),
        cache=CacheConfig(enabled=False),
        base_url="http://localhost:8000",
    )
    kwargs.update(overrides)
    return AuthConfig(**kwargs)


@pytest.fixture
def make_config():
    """Factory fixture: build a valid development config with overrides."""
    return _make_config


@pytest.fixture
def config() -> AuthConfig:
    """A valid development configuration."""
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
def jwt_manager(config: AuthConfig) -> JWTTokenManager:
    return JWTTokenManager(config)


@pytest.fixture
def security_manager(
    db: InMemoryDatabase, cache: InMemoryCache, config: AuthConfig
) -> SecurityManager:
    return SecurityManager(db, cache, config)
