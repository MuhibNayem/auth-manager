"""Passkey tests: per-user challenge keys, library challenges, single-use."""

from __future__ import annotations

import pytest

import webauthn
from authy_package.errors import AuthenticationError
from authy_package.passwordless.passkey import (
    AUTH_CHALLENGE_KEY_TEMPLATE,
    REG_CHALLENGE_KEY_TEMPLATE,
    PasskeyManager,
)


@pytest.fixture
async def passkey_user(db):
    return await db.create_user({"email": "pk@example.com", "username": "pk"})


@pytest.fixture
def pk(config, db, cache):
    return PasskeyManager(config, db, cache)


async def test_register_start_stores_per_user_challenge(pk, db, cache, passkey_user):
    options = await pk.register_start(passkey_user["id"], "pk@example.com")
    assert options["challenge"]  # library-generated challenge present

    record = await cache.get_json(
        REG_CHALLENGE_KEY_TEMPLATE.format(user_id=passkey_user["id"])
    )
    assert record is not None
    assert record["type"] == "registration"
    assert record["challenge"] == options["challenge"]


async def test_registration_challenges_are_per_user(pk, db, cache):
    u1 = await db.create_user({"email": "a@example.com", "username": "a"})
    u2 = await db.create_user({"email": "b@example.com", "username": "b"})
    o1 = await pk.register_start(u1["id"], "a@example.com")
    o2 = await pk.register_start(u2["id"], "b@example.com")
    assert o1["challenge"] != o2["challenge"]

    r1 = await cache.get_json(REG_CHALLENGE_KEY_TEMPLATE.format(user_id=u1["id"]))
    r2 = await cache.get_json(REG_CHALLENGE_KEY_TEMPLATE.format(user_id=u2["id"]))
    assert r1["challenge"] == o1["challenge"]
    assert r2["challenge"] == o2["challenge"]


async def test_register_complete_consumes_challenge_and_stores_credential(
    pk, db, cache, passkey_user, monkeypatch
):
    class _FakeVerification:
        credential_id = b"cred-id-bytes"
        credential_public_key = b"public-key-bytes"
        sign_count = 3

    monkeypatch.setattr(
        webauthn, "verify_registration_response", lambda **kw: _FakeVerification()
    )

    options = await pk.register_start(passkey_user["id"], "pk@example.com")
    stored = await pk.register_complete(
        passkey_user["id"], {"id": "whatever", "response": {}}
    )
    assert stored["counter"] == 3

    # Challenge is single-use: no pending registration remains.
    assert (
        await cache.get_json(REG_CHALLENGE_KEY_TEMPLATE.format(user_id=passkey_user["id"]))
        is None
    )
    with pytest.raises(AuthenticationError):
        await pk.register_complete(passkey_user["id"], {"id": "x", "response": {}})

    passkeys = await pk.list_passkeys(passkey_user["id"])
    assert len(passkeys) == 1


async def test_register_complete_without_challenge_fails(pk, passkey_user):
    with pytest.raises(AuthenticationError):
        await pk.register_complete(passkey_user["id"], {"id": "x", "response": {}})


async def test_authenticate_start_stores_per_user_challenge_key(
    pk, db, cache, passkey_user
):
    options = await pk.authenticate_start(passkey_user["id"])
    challenge = options["challenge"]
    key = AUTH_CHALLENGE_KEY_TEMPLATE.format(
        user_id=passkey_user["id"], challenge=challenge
    )
    record = await cache.get_json(key)
    assert record is not None
    assert record["type"] == "authentication"
    assert record["challenge"] == challenge


async def test_authenticate_complete_verifies_and_updates_counter(
    pk, db, cache, passkey_user, monkeypatch
):
    class _Reg:
        credential_id = b"cred-1"
        credential_public_key = b"pub"
        sign_count = 1

    class _Auth:
        new_sign_count = 7

    monkeypatch.setattr(webauthn, "verify_registration_response", lambda **kw: _Reg())
    monkeypatch.setattr(webauthn, "verify_authentication_response", lambda **kw: _Auth())

    await pk.register_start(passkey_user["id"], "pk@example.com")
    await pk.register_complete(passkey_user["id"], {"id": "cred-1-b64", "response": {}})

    options = await pk.authenticate_start(passkey_user["id"])
    challenge = options["challenge"]
    cred_b64 = (await pk.list_passkeys(passkey_user["id"]))[0]["credential_id"]

    result = await pk.authenticate_complete(
        passkey_user["id"], challenge, {"id": cred_b64}
    )
    assert result["user"]["id"] == passkey_user["id"]

    updated = (await pk.list_passkeys(passkey_user["id"]))[0]
    assert updated["counter"] == 7

    # Challenge consumed -> replay fails.
    with pytest.raises(AuthenticationError):
        await pk.authenticate_complete(passkey_user["id"], challenge, {"id": cred_b64})
