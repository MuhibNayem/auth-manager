"""Core traditional-auth tests: login security, rotation, legacy upgrade."""

from __future__ import annotations

import base64
import hashlib

import pytest

from tessera.core.auth_manager import sanitize_user
from tessera.errors import AuthenticationError, RateLimitError, TokenError

PASSWORD = "Str0ng!Passw0rd#2024"


# -- registration --------------------------------------------------------------

async def test_register_user_strips_hash(auth, db):
    result = await auth.register_user(
        username="bob", email="bob@example.com", password=PASSWORD
    )
    assert result["message"] == "User registered successfully."
    assert "hashed_password" not in result["user"]
    stored = await db.get_user_by_identifier(email="bob@example.com")
    assert stored["hashed_password"].startswith(("$2a$", "$2b$", "$2y$"))


async def test_register_requires_identifier_and_password(auth):
    with pytest.raises(ValueError):
        await auth.register_user(password=PASSWORD)
    with pytest.raises(ValueError):
        await auth.register_user(email="x@example.com", password="")


# -- login ------------------------------------------------------------------------

async def test_login_success_returns_tokens_and_session(auth, registered_user):
    result = await auth.login_user(email="alice@example.com", password=PASSWORD)
    assert result["message"] == "Login successful."
    assert result["access_token"] and result["refresh_token"]
    assert result["session_id"]
    assert "hashed_password" not in result["user"]
    assert "mfa_secret" not in result["user"]


async def test_login_identical_error_for_bad_user_and_bad_password(
    auth, registered_user
):
    with pytest.raises(AuthenticationError) as bad_user:
        await auth.login_user(email="ghost@example.com", password=PASSWORD)
    with pytest.raises(AuthenticationError) as bad_password:
        await auth.login_user(email="alice@example.com", password="Wrong!Pass1")
    assert bad_user.value.message == bad_password.value.message
    assert bad_user.value.code == bad_password.value.code == "authentication_failed"


async def test_login_inactive_user_rejected(auth, db, registered_user):
    await db.update_user(registered_user["id"], {"is_active": False})
    with pytest.raises(AuthenticationError) as exc:
        await auth.login_user(email="alice@example.com", password=PASSWORD)
    assert exc.value.code == "authentication_failed"


async def test_login_rate_limit_and_lockout(auth, registered_user):
    # 5 failures trip the lockout (config.rate_limit_max_attempts=5)
    for _ in range(5):
        with pytest.raises(AuthenticationError):
            await auth.login_user(email="alice@example.com", password="Wrong!Pass1")
    # Even the CORRECT password is now blocked by the lockout marker.
    with pytest.raises(AuthenticationError) as locked:
        await auth.login_user(email="alice@example.com", password=PASSWORD)
    assert locked.value.code == "account_locked"


async def test_successful_login_clears_failure_counter(auth, registered_user):
    for _ in range(3):
        with pytest.raises(AuthenticationError):
            await auth.login_user(email="alice@example.com", password="Wrong!Pass1")
    ok = await auth.login_user(email="alice@example.com", password=PASSWORD)
    assert ok["access_token"]
    # Failures reset: another 3 failures still under the budget.
    for _ in range(3):
        with pytest.raises(AuthenticationError):
            await auth.login_user(email="alice@example.com", password="Wrong!Pass1")


# -- refresh rotation -----------------------------------------------------------------

async def test_refresh_rotates_and_blocks_replay(auth, registered_user):
    login = await auth.login_user(email="alice@example.com", password=PASSWORD)
    old_refresh = login["refresh_token"]

    rotated = await auth.refresh_token(old_refresh)
    assert rotated["access_token"] != login["access_token"]
    assert rotated["refresh_token"] != old_refresh

    # Replaying the consumed refresh token must fail.
    with pytest.raises(AuthenticationError) as replay:
        await auth.refresh_token(old_refresh)
    assert replay.value.code == "refresh_token_reused"

    # The new refresh token works.
    again = await auth.refresh_token(rotated["refresh_token"])
    assert again["access_token"]


async def test_refresh_rejects_access_token(auth, registered_user):
    login = await auth.login_user(email="alice@example.com", password=PASSWORD)
    with pytest.raises(TokenError):
        await auth.refresh_token(login["access_token"])


async def test_refresh_rejects_garbage(auth, registered_user):
    with pytest.raises(TokenError):
        await auth.refresh_token("not-a-jwt")


# -- logout ------------------------------------------------------------------------------

async def test_logout_revokes_session(auth, db, registered_user):
    login = await auth.login_user(email="alice@example.com", password=PASSWORD)
    await auth.logout_user(access_token=login["access_token"])
    sessions = await db.get_active_sessions(registered_user["id"])
    assert sessions == []


# -- legacy hash upgrade ------------------------------------------------------------------

def _django_hash(password: str, salt: str = "s4lt", iterations: int = 100) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), iterations
    )
    return f"pbkdf2_sha256${iterations}${salt}${base64.b64encode(digest).decode()}"


async def test_login_upgrades_django_legacy_hash(auth, db):
    await db.create_user(
        {
            "username": "legacy",
            "email": "legacy@example.com",
            "legacy_password_hash": {
                "hash": _django_hash("Legacy!Pass1"),
                "algorithm": "pbkdf2_sha256",
                "provider": "django",
            },
            "password_algorithm": "pbkdf2_sha256",
        }
    )
    result = await auth.login_user(email="legacy@example.com", password="Legacy!Pass1")
    assert result["access_token"]

    upgraded = await db.get_user_by_identifier(email="legacy@example.com")
    assert upgraded["password_algorithm"] == "bcrypt"
    assert upgraded["hashed_password"].startswith(("$2a$", "$2b$", "$2y$"))
    assert upgraded.get("legacy_password_hash") is None

    # Second login goes through the bcrypt path.
    again = await auth.login_user(email="legacy@example.com", password="Legacy!Pass1")
    assert again["access_token"]


async def test_login_legacy_hash_wrong_password(auth, db):
    await db.create_user(
        {
            "username": "legacy2",
            "email": "legacy2@example.com",
            "legacy_password_hash": {
                "hash": _django_hash("Legacy!Pass1"),
                "algorithm": "pbkdf2_sha256",
                "provider": "django",
            },
            "password_algorithm": "pbkdf2_sha256",
        }
    )
    with pytest.raises(AuthenticationError):
        await auth.login_user(email="legacy2@example.com", password="Wrong!Pass1")


# -- sanitize -------------------------------------------------------------------------------

def test_sanitize_user_strips_all_secret_fields():
    user = {
        "id": "1",
        "email": "a@b.c",
        "hashed_password": "x",
        "password_hash": "x",
        "legacy_password_hash": {"hash": "x"},
        "mfa_secret": "x",
        "mfa_backup_codes": ["x"],
        "password_algorithm": "bcrypt",
    }
    clean = sanitize_user(user)
    for field in (
        "hashed_password",
        "password_hash",
        "legacy_password_hash",
        "mfa_secret",
        "mfa_backup_codes",
        "password_algorithm",
    ):
        assert field not in clean
    assert clean["email"] == "a@b.c"
