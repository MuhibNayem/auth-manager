"""OIDC tests: state/nonce enforcement, PKCE, basic-auth, azp, padding."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tessera.errors import AuthenticationError, ConfigError
from tessera.oidc import OIDCConfig, OIDCManager

ISSUER = "https://idp.example.com"
CLIENT_ID = "test-client"


def _config(**kw):
    defaults = dict(
        client_id=CLIENT_ID,
        client_secret="secret",
        redirect_uri="https://app.example.com/cb",
        issuer=ISSUER,
        authorization_endpoint="https://idp.example.com/authorize",
        token_endpoint="https://idp.example.com/token",
        userinfo_endpoint="https://idp.example.com/userinfo",
        jwks_uri="https://idp.example.com/jwks",
    )
    defaults.update(kw)
    return OIDCConfig(**defaults)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


@pytest.fixture
def rsa_jwk():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": "k1",
        "n": _b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
        "e": _b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")),
    }
    return key, jwk


def test_constructor_requires_cache_or_db():
    with pytest.raises(ConfigError):
        OIDCManager(_config(), database=None, cache=None)


async def test_state_generated_stored_and_single_use(cache):
    manager = OIDCManager(_config(), database=None, cache=cache)
    url, state, verifier = await manager.create_authorization_url_async()
    assert "state=" in url and verifier
    assert await cache.get(f"tessera:oauth:state:{state}") is not None

    captured = {}

    async def fake_request(data, headers):
        captured.update({"data": data, "headers": headers})
        return {"access_token": "at", "token_type": "Bearer", "expires_in": 3600}

    manager._request_tokens = fake_request
    tokens = await manager.exchange_code_for_tokens("code", state, verifier)
    assert tokens["access_token"] == "at"

    # State consumed -> replay rejected.
    with pytest.raises(AuthenticationError) as replay:
        await manager.exchange_code_for_tokens("code", state, verifier)
    assert replay.value.code == "oidc_state_invalid"


async def test_unknown_state_rejected(cache):
    manager = OIDCManager(_config(), database=None, cache=cache)
    with pytest.raises(AuthenticationError) as exc:
        await manager.exchange_code_for_tokens("code", "never-issued", "v")
    assert exc.value.code == "oidc_state_invalid"


async def test_public_client_requires_pkce(cache):
    cfg = _config(client_secret=None)  # public client
    manager = OIDCManager(cfg, database=None, cache=cache)
    # Store a state record WITHOUT a verifier.
    await manager._save_pending_state({"state": "s1", "nonce": "n1"})
    with pytest.raises(ValueError):
        await manager.exchange_code_for_tokens("code", "s1", None)


async def test_client_secret_basic_header(cache):
    cfg = _config(token_endpoint_auth_method="client_secret_basic")
    manager = OIDCManager(cfg, database=None, cache=cache)
    captured = {}

    async def fake_request(data, headers):
        captured.update({"data": data, "headers": headers})
        return {"access_token": "at", "expires_in": 3600}

    manager._request_tokens = fake_request
    url, state, verifier = await manager.create_authorization_url_async()
    await manager.exchange_code_for_tokens("code", state, verifier)

    assert captured["headers"]["Authorization"].startswith("Basic ")
    assert "client_secret" not in captured["data"]
    # Decode the basic header -> id:secret
    decoded = base64.b64decode(
        captured["headers"]["Authorization"].split(" ", 1)[1]
    ).decode()
    assert decoded == f"{CLIENT_ID}:secret"


async def test_client_secret_post_body(cache):
    manager = OIDCManager(_config(), database=None, cache=cache)
    captured = {}

    async def fake_request(data, headers):
        captured.update({"data": data, "headers": headers})
        return {"access_token": "at", "expires_in": 3600}

    manager._request_tokens = fake_request
    _url, state, verifier = await manager.create_authorization_url_async()
    await manager.exchange_code_for_tokens("code", state, verifier)
    assert captured["data"]["client_secret"] == "secret"
    assert "Authorization" not in captured["headers"]


async def test_nonce_mismatch_and_azp(cache, rsa_jwk, monkeypatch):
    key, jwk = rsa_jwk
    cfg = _config()
    manager = OIDCManager(cfg, database=None, cache=cache)

    async def fake_jwks(force_refresh=False):
        return {"keys": [jwk]}

    monkeypatch.setattr(cfg, "get_jwks", fake_jwks)

    now = datetime.now(timezone.utc)

    def make_token(aud, nonce="n1", azp=None):
        payload = {
            "sub": "u1",
            "aud": aud,
            "iss": ISSUER,
            "exp": now + timedelta(minutes=10),
            "iat": now,
            "nonce": nonce,
        }
        if azp:
            payload["azp"] = azp
        return pyjwt.encode(payload, key, algorithm="RS256", headers={"kid": "k1"})

    # Nonce mismatch -> rejected.
    token = make_token(aud=CLIENT_ID, nonce="attacker-nonce")
    with pytest.raises(AuthenticationError) as nonce_exc:
        await manager.validate_id_token(token, expected_nonce="n1")
    assert nonce_exc.value.code == "oidc_nonce_mismatch"

    # Multi-audience without azp -> rejected.
    token2 = make_token(aud=[CLIENT_ID, "other-aud"], nonce="n1")
    with pytest.raises(AuthenticationError) as azp_exc:
        await manager.validate_id_token(token2, expected_nonce="n1")
    assert azp_exc.value.code == "oidc_azp_mismatch"

    # Multi-audience WITH correct azp -> accepted.
    token3 = make_token(aud=[CLIENT_ID, "other-aud"], nonce="n1", azp=CLIENT_ID)
    payload = await manager.validate_id_token(token3, expected_nonce="n1")
    assert payload["sub"] == "u1"


async def test_jwks_refreshed_once_on_unknown_kid(cache, rsa_jwk, monkeypatch):
    key, jwk = rsa_jwk
    cfg = _config()
    manager = OIDCManager(cfg, database=None, cache=cache)
    calls = {"count": 0}

    async def fake_jwks(force_refresh=False):
        calls["count"] += 1
        # First (cached) call returns empty; the forced refresh returns the key.
        if force_refresh:
            return {"keys": [jwk]}
        return {"keys": []}

    monkeypatch.setattr(cfg, "get_jwks", fake_jwks)
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "u",
        "aud": CLIENT_ID,
        "iss": ISSUER,
        "exp": now + timedelta(minutes=5),
        "iat": now,
    }
    token = pyjwt.encode(payload, key, algorithm="RS256", headers={"kid": "k1"})
    result = await manager.validate_id_token(token)
    assert result["sub"] == "u"
    assert calls["count"] == 2  # initial miss + one forced refresh


def test_b64url_padding_idiom():
    from tessera.oidc.oidc_manager import _b64url_decode

    for length in range(1, 10):
        original = bytes(range(length))
        encoded = base64.urlsafe_b64encode(original).decode().rstrip("=")
        assert _b64url_decode(encoded) == original


async def test_token_cache_keyed_by_full_sha256(cache):
    import hashlib

    manager = OIDCManager(_config(), database=None, cache=cache)

    async def fake_request(data, headers):
        return {"access_token": "the-full-access-token", "expires_in": 3600}

    manager._request_tokens = fake_request
    _url, state, verifier = await manager.create_authorization_url_async()
    await manager.exchange_code_for_tokens("code", state, verifier)

    expected_key = "tessera:oidc:tokens:" + hashlib.sha256(
        b"the-full-access-token"
    ).hexdigest()
    assert await cache.get_json(expected_key) is not None
