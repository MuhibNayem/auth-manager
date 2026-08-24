"""MFA tests: confirm-before-enable, attempt limiting, single-use backups."""

from __future__ import annotations

import hashlib

import pyotp
import pytest

from tessera.errors import AuthenticationError, RateLimitError

EMAIL = "mfa-user@example.com"


@pytest.fixture
async def mfa_user(db):
    user = await db.create_user(
        {"username": "mfauser", "email": EMAIL, "mfa_enabled": False}
    )
    return user


async def test_setup_does_not_enable_until_confirmed(mfa_manager, db, mfa_user):
    setup = await mfa_manager.setup_mfa(email=EMAIL)
    assert setup["pending"] is True
    assert setup["mfa_secret"]

    # Still NOT enabled before confirmation.
    user = await db.get_user_by_identifier(email=EMAIL)
    assert user.get("mfa_enabled") is False


async def test_confirm_with_wrong_code_fails_and_correct_code_enables(
    mfa_manager, db, mfa_user
):
    setup = await mfa_manager.setup_mfa(email=EMAIL)
    with pytest.raises(AuthenticationError):
        await mfa_manager.confirm_mfa("000000", email=EMAIL)

    code = pyotp.TOTP(setup["mfa_secret"]).now()
    result = await mfa_manager.confirm_mfa(code, email=EMAIL)
    assert len(result["backup_codes"]) == 8

    user = await db.get_user_by_identifier(email=EMAIL)
    assert user["mfa_enabled"] is True
    # Backup codes are stored hashed (sha256), never plaintext.
    expected = hashlib.sha256(result["backup_codes"][0].lower().encode()).hexdigest()
    assert expected in user["mfa_backup_codes"]
    assert result["backup_codes"][0] not in user["mfa_backup_codes"]


async def test_confirm_requires_pending_setup(mfa_manager, mfa_user):
    with pytest.raises(AuthenticationError):
        await mfa_manager.confirm_mfa("123456", email=EMAIL)


async def test_backup_code_is_single_use(mfa_manager, db, mfa_user):
    setup = await mfa_manager.setup_mfa(email=EMAIL)
    code = pyotp.TOTP(setup["mfa_secret"]).now()
    confirmed = await mfa_manager.confirm_mfa(code, email=EMAIL)
    backup = confirmed["backup_codes"][0]

    assert await mfa_manager.use_backup_code(backup, email=EMAIL) is True
    with pytest.raises(AuthenticationError):
        await mfa_manager.use_backup_code(backup, email=EMAIL)


async def test_verify_mfa_code_attempt_limiting(mfa_manager, db, mfa_user, config):
    setup = await mfa_manager.setup_mfa(email=EMAIL)
    code = pyotp.TOTP(setup["mfa_secret"]).now()
    await mfa_manager.confirm_mfa(code, email=EMAIL)

    # Exhaust the attempt budget with bad codes.
    for _ in range(config.rate_limit_max_attempts):
        with pytest.raises(AuthenticationError):
            await mfa_manager.verify_mfa_code("000000", email=EMAIL)

    # Now even a VALID code is rate-limited.
    good = pyotp.TOTP(setup["mfa_secret"]).now()
    with pytest.raises(RateLimitError):
        await mfa_manager.verify_mfa_code(good, email=EMAIL)


async def test_login_gate_requires_and_verifies_mfa(
    auth, mfa_manager, db, mfa_user
):
    await db.update_user(mfa_user["id"], {"hashed_password": _bcrypt("P@ssw0rd12345!")})
    setup = await mfa_manager.setup_mfa(email=EMAIL)
    totp_code = pyotp.TOTP(setup["mfa_secret"]).now()
    await mfa_manager.confirm_mfa(totp_code, email=EMAIL)

    # Missing code -> mfa_required error.
    with pytest.raises(AuthenticationError) as missing:
        await auth.login_user(email=EMAIL, password="P@ssw0rd12345!")
    assert missing.value.code == "mfa_required"

    # Correct code -> success.
    good = pyotp.TOTP(setup["mfa_secret"]).now()
    result = await auth.login_user(email=EMAIL, password="P@ssw0rd12345!", mfa_code=good)
    assert result["access_token"]


def _bcrypt(password: str) -> str:
    from tessera.utils.security import hash_password

    return hash_password(password, bcrypt_rounds=4)
