"""Admin auth tests: login, lockout, refresh rotation, bearer-only auth."""

from __future__ import annotations

import pytest

@pytest.mark.asyncio
async def test_unauthenticated_v1_and_v2_return_401(client):
    """No bearer → 401 on both admin surfaces (CONTRACTS §5/§8)."""
    v1 = await client.get("/admin/api/v1/users")
    assert v1.status_code == 401
    assert v1.headers.get("WWW-Authenticate") == "Bearer"
    v2 = await client.get("/admin/v2/api-keys")
    assert v2.status_code == 401


@pytest.mark.asyncio
async def test_token_via_query_param_is_rejected(client, admin_headers, token_manager):
    """Tokens in query parameters must never authenticate (bearer only)."""
    token = admin_headers["Authorization"].removeprefix("Bearer ")
    response = await client.get(f"/admin/api/v1/users?token={token}")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_happy_path_returns_tokens_and_user(client, admin_credentials):
    response = await client.post(
        "/admin/api/v1/auth/login",
        json=admin_credentials,
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["user"]["email"] == admin_credentials["username_or_email"]
    assert "hashed_password" not in data["user"]


@pytest.mark.asyncio
async def test_login_bad_password_and_unknown_user_are_identical(client, admin_credentials):
    bad_password = await client.post(
        "/admin/api/v1/auth/login",
        json={"username_or_email": admin_credentials["username_or_email"], "password": "wrong-password"},
    )
    unknown_user = await client.post(
        "/admin/api/v1/auth/login",
        json={"username_or_email": "ghost@example.com", "password": "whatever"},
    )
    assert bad_password.status_code == 401
    assert unknown_user.status_code == 401
    assert bad_password.json()["message"] == unknown_user.json()["message"]


@pytest.mark.asyncio
async def test_lockout_after_n_failures_blocks_even_correct_password(client, admin_credentials):
    """rate_limit_max_attempts=3 in the test config engages lockout."""
    for _ in range(3):
        failed = await client.post(
            "/admin/api/v1/auth/login",
            json={"username_or_email": admin_credentials["username_or_email"], "password": "wrong-password"},
        )
        assert failed.status_code == 401
    locked = await client.post(
        "/admin/api/v1/auth/login",
        json=admin_credentials,
    )
    assert locked.status_code == 401
    assert locked.json()["error"] == "account_locked"


@pytest.mark.asyncio
async def test_non_admin_user_cannot_login_to_admin_api(client, db, config):
    from tessera.utils.security import hash_password

    await db.create_user(
        {
            "username": "regular",
            "email": "regular@example.com",
            "hashed_password": hash_password(
                "RegularPass!23", bcrypt_rounds=config.bcrypt_rounds
            ),
            "role": "user",
        }
    )
    response = await client.post(
        "/admin/api/v1/auth/login",
        json={"username_or_email": "regular@example.com", "password": "RegularPass!23"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_refresh_rotation_invalidates_old_token(client, admin_headers, admin_credentials):
    login = await client.post(
        "/admin/api/v1/auth/login",
        json=admin_credentials,
    )
    refresh_token = login.json()["refresh_token"]

    first = await client.post(
        "/admin/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert first.status_code == 200, first.text
    assert first.json()["access_token"]

    replay = await client.post(
        "/admin/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert replay.status_code == 401


@pytest.mark.asyncio
async def test_refresh_rejects_access_token_type(client, admin_headers):
    access_token = admin_headers["Authorization"].removeprefix("Bearer ")
    response = await client.post(
        "/admin/api/v1/auth/refresh", json={"refresh_token": access_token}
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_health_endpoint_reports_components(client, admin_headers):
    response = await client.get("/admin/api/v1/health", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["components"]["database"] == "healthy"
    assert data["components"]["cache"] == "healthy"
