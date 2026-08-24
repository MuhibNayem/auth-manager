"""Shared fixtures for the platform/admin test suite.

Builds a fully wired admin app on InMemoryDatabase + InMemoryCache +
JWTTokenManager (CONTRACTS.md §5). No network is used anywhere: DNS
lookups in webhook tests are monkeypatched, and HTTP delivery uses
httpx MockTransport.
"""

from __future__ import annotations

import secrets
from typing import Any, AsyncIterator, Dict

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

from tessera.admin.audit_logger import AuditLogger
from tessera.admin.dashboard_api import create_admin_app
from tessera.admin.deps import AdminDependencies
from tessera.admin.rbac_manager import RBACManager
from tessera.cache import InMemoryCache
from tessera.config import AuthConfig, CacheConfig, DatabaseConfig
from tessera.db import InMemoryDatabase
from tessera.organizations.org_manager import OrganizationManager
from tessera.utils.security import JWTTokenManager, hash_password
from tessera.webhooks.webhook_manager import WebhookManager

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "Adm1n!Passw0rd"


def _test_jwt_secret() -> str:
    """A strong secret that can never trip placeholder detection.

    ``token_hex`` output is pure [0-9a-f], which cannot contain any of the
    placeholder markers checked by ``AuthConfig.validate()`` (unlike
    ``token_urlsafe``, whose alphabet can rarely produce e.g. 'xxx').
    """
    return "platform-admin-test-" + secrets.token_hex(16)


def _make_config(**overrides: Any) -> AuthConfig:
    """Valid development config backed by the memory database."""
    kwargs: Dict[str, Any] = dict(
        env="development",
        jwt_secret=_test_jwt_secret(),
        bcrypt_rounds=4,  # test speed; validate() accepts 4..31
        rate_limit_enabled=True,
        rate_limit_max_attempts=3,
        rate_limit_window_seconds=300,
        account_lockout_duration_seconds=900,
        database=DatabaseConfig(db_type="memory"),
        cache=CacheConfig(enabled=False),
        base_url="http://localhost:8000",
    )
    kwargs.update(overrides)
    return AuthConfig(**kwargs)


@pytest.fixture
def config() -> AuthConfig:
    cfg = _make_config()
    assert cfg.validate() is True
    return cfg


@pytest_asyncio.fixture
async def db() -> AsyncIterator[InMemoryDatabase]:
    database = InMemoryDatabase()
    await database.connect()
    yield database


@pytest.fixture
def cache() -> InMemoryCache:
    return InMemoryCache()


@pytest.fixture
def token_manager(config: AuthConfig) -> JWTTokenManager:
    return JWTTokenManager(config)


@pytest_asyncio.fixture
async def admin_user(db: InMemoryDatabase, config: AuthConfig) -> Dict[str, Any]:
    """The seeded platform admin (role=admin)."""
    return await db.create_user(
        {
            "username": "admin",
            "email": ADMIN_EMAIL,
            "hashed_password": hash_password(
                ADMIN_PASSWORD,
                algorithm=config.password_hash_algorithm,
                bcrypt_rounds=config.bcrypt_rounds,
            ),
            "role": "admin",
            "is_active": True,
        }
    )


@pytest_asyncio.fixture
async def wired_app(
    config: AuthConfig,
    db: InMemoryDatabase,
    cache: InMemoryCache,
    token_manager: JWTTokenManager,
    admin_user: Dict[str, Any],
) -> AsyncIterator[FastAPI]:
    """A FastAPI app wired exactly per CONTRACTS §5."""
    audit_logger = AuditLogger(db)
    rbac = await RBACManager.create(db)
    orgs = OrganizationManager(db, cache=cache)
    webhooks = WebhookManager(config, db, cache)
    deps = AdminDependencies(
        config=config,
        db=db,
        cache=cache,
        token_manager=token_manager,
        audit_logger=audit_logger,
        rbac=rbac,
        orgs=orgs,
        webhooks=webhooks,
    )
    app = create_admin_app(deps)
    yield app
    await webhooks.close()


@pytest_asyncio.fixture
async def client(wired_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Async ASGI client against the wired admin app."""
    transport = httpx.ASGITransport(app=wired_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as http_client:
        yield http_client


@pytest_asyncio.fixture
async def admin_headers(client: httpx.AsyncClient) -> Dict[str, str]:
    """Bearer headers for the seeded admin via POST /auth/login."""
    response = await client.post(
        "/admin/api/v1/auth/login",
        json={"username_or_email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert "access_token" in data and "refresh_token" in data and "user" in data
    return {"Authorization": f"Bearer {data['access_token']}"}



@pytest_asyncio.fixture
async def orgs(db: InMemoryDatabase, cache: InMemoryCache) -> OrganizationManager:
    """Standalone organization manager for manager-level tests."""
    return OrganizationManager(db, cache=cache)


@pytest.fixture
def admin_credentials() -> Dict[str, str]:
    """Login credentials of the seeded platform admin."""
    return {"username_or_email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
