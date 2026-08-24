"""Migration tests: honest registry, preview fix, legacy hash upgrade."""

from __future__ import annotations

import base64
import hashlib

import pytest

from authy_package.migration import (
    Auth0Importer,
    DjangoImporter,
    FirebaseImporter,
    get_importer,
    verify_and_upgrade_legacy_hash,
)


def test_registry_honesty_cognito_and_supabase_not_implemented(db):
    with pytest.raises(NotImplementedError) as cognito:
        get_importer("cognito", {}, db)
    assert "not implemented" in str(cognito.value)

    with pytest.raises(NotImplementedError) as supabase:
        get_importer("supabase", {}, db)
    assert "not implemented" in str(supabase.value)


def test_registry_returns_real_importers(db):
    assert isinstance(get_importer("firebase", {}, db), FirebaseImporter)
    assert isinstance(get_importer("auth0", {}, db), Auth0Importer)
    assert isinstance(get_importer("django", {}, db), DjangoImporter)


def test_registry_unknown_provider_raises_value_error(db):
    with pytest.raises(ValueError):
        get_importer("okta", {}, db)


def test_preview_migration_does_not_raise_stop_iteration(db):
    importer = get_importer("django", {}, db)
    preview = importer.preview_migration()
    assert preview["provider"] == "django"
    assert preview["strategy"] == "lazy-password-migration"
    assert "estimated_users" in preview


# -- legacy hash verification + upgrade ---------------------------------------

def _django_hash(password: str, salt: str = "s4lt", iterations: int = 100) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${base64.b64encode(dk).decode()}"


async def test_verify_and_upgrade_django_pbkdf2(db):
    user = await db.create_user(
        {
            "email": "d@example.com",
            "legacy_password_hash": {
                "hash": _django_hash("Legacy!Pass1"),
                "algorithm": "pbkdf2_sha256",
                "provider": "django",
            },
            "password_algorithm": "pbkdf2_sha256",
        }
    )
    ok = await verify_and_upgrade_legacy_hash(user, "Legacy!Pass1", db)
    assert ok is True

    upgraded = await db.get_user_by_id(user["id"])
    assert upgraded["password_algorithm"] == "bcrypt"
    assert upgraded["hashed_password"].startswith(("$2a$", "$2b$", "$2y$"))
    assert upgraded.get("legacy_password_hash") is None
    assert upgraded.get("password_hash") is None


async def test_verify_django_wrong_password_returns_false(db):
    user = await db.create_user(
        {
            "email": "d2@example.com",
            "legacy_password_hash": {
                "hash": _django_hash("Legacy!Pass1"),
                "algorithm": "pbkdf2_sha256",
            },
            "password_algorithm": "pbkdf2_sha256",
        }
    )
    assert await verify_and_upgrade_legacy_hash(user, "Wrong!", db) is False


def _firebase_scrypt_hash(password, signer_key_b64, salt_b64, salt_sep_b64, rounds, memory_cost):
    """Build a hash with the same pipeline the verifier implements."""
    salt_bytes = base64.b64decode(salt_b64) + base64.b64decode(salt_sep_b64)
    derived = hashlib.scrypt(
        password.encode(),
        salt=salt_bytes,
        n=1 << rounds,
        r=memory_cost,
        p=1,
        dklen=32,
        maxmem=256 * 1024 * 1024,
    )
    signer = base64.b64decode(signer_key_b64)
    xored = bytes(b ^ signer[i % len(signer)] for i, b in enumerate(derived))
    return base64.b64encode(xored).decode()


async def test_verify_and_upgrade_firebase_scrypt_memoized(db):
    signer_key = base64.b64encode(b"0123456789abcdef").decode()
    salt = base64.b64encode(b"somesalt").decode()
    salt_sep = base64.b64encode(b"\x07").decode()
    stored = _firebase_scrypt_hash("Scrypt!Pass1", signer_key, salt, salt_sep, 8, 14)

    user = await db.create_user(
        {
            "email": "f@example.com",
            "legacy_password_hash": {
                "hash": stored,
                "algorithm": "scrypt",
                "salt": salt,
                "signer_key": signer_key,
                "rounds": 8,
                "memory_cost": 14,
                "salt_separator": salt_sep,
            },
            "password_algorithm": "scrypt",
        }
    )
    assert await verify_and_upgrade_legacy_hash(user, "Scrypt!Pass1", db) is True
    upgraded = await db.get_user_by_id(user["id"])
    assert upgraded["password_algorithm"] == "bcrypt"

    # Second user reuses memoized scrypt params (same key material).
    user2 = await db.create_user(
        {
            "email": "f2@example.com",
            "legacy_password_hash": {
                "hash": _firebase_scrypt_hash("Other!Pass1", signer_key, salt, salt_sep, 8, 14),
                "algorithm": "scrypt",
                "salt": salt,
                "signer_key": signer_key,
                "rounds": 8,
                "memory_cost": 14,
                "salt_separator": salt_sep,
            },
            "password_algorithm": "scrypt",
        }
    )
    assert await verify_and_upgrade_legacy_hash(user2, "Other!Pass1", db) is True


async def test_unsupported_algorithm_returns_false(db):
    user = await db.create_user(
        {
            "email": "u@example.com",
            "legacy_password_hash": {"hash": "x", "algorithm": "md5_custom"},
            "password_algorithm": "md5_custom",
        }
    )
    assert await verify_and_upgrade_legacy_hash(user, "anything", db) is False
