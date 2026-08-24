"""Regression tests for the wave-3 independent security review hardening.

Covers review findings NEW-1 (placeholder detector false positives),
NEW-2 (SAML signed-assertion replay), NEW-3 (social linking by display
name), NEW-4 (webhook SSRF CGNAT gap), NEW-5 (OIDC issuer required) and
NEW-8 (Apple OAuth state validation).
"""

import secrets

import pytest

from tessera.errors import AuthenticationError, ConfigError


# -- NEW-1: placeholder detection without false positives ---------------------

def test_random_high_entropy_secrets_validate(make_config) -> None:
    for _ in range(300):
        cfg = make_config(jwt_secret=secrets.token_urlsafe(32))
        assert cfg.validate() is True


def test_classic_placeholders_still_rejected(make_config) -> None:
    for bad in (
        "changeme-please",
        "your-super-secret-key-min-32-chars",
        "your-secret-key",
        "placeholder-key",
        "abc-xxx-def",
        "my_dummy_value",
    ):
        cfg = make_config(jwt_secret=bad)
        with pytest.raises(ConfigError):
            cfg.validate()


# -- NEW-4: webhook SSRF blocks RFC6598 shared (CGNAT) space ------------------

def test_webhook_cgnat_address_rejected() -> None:
    from tessera.webhooks.webhook_manager import validate_endpoint_url

    with pytest.raises(ValueError, match="forbidden address"):
        validate_endpoint_url("https://100.64.0.10/hook", env="development")
    with pytest.raises(ValueError, match="forbidden address"):
        validate_endpoint_url("https://100.127.255.254/hook", env="development")


def test_webhook_public_address_allowed() -> None:
    from tessera.webhooks.webhook_manager import validate_endpoint_url

    assert validate_endpoint_url("https://93.184.216.34/hook", env="development")


# -- NEW-5: OIDC ID-token validation requires a configured issuer -------------

async def test_oidc_validate_id_token_requires_issuer() -> None:
    from tessera.cache.memory_cache import InMemoryCache
    from tessera.db.memory import InMemoryDatabase
    from tessera.oidc.oidc_manager import OIDCConfig, OIDCManager

    db = InMemoryDatabase()
    await db.connect()
    cfg = OIDCConfig(
        client_id="cid", client_secret=None, redirect_uri="https://app/cb", issuer=None
    )
    manager = OIDCManager(cfg, database=db, cache=InMemoryCache())
    with pytest.raises(ConfigError, match="issuer"):
        await manager.validate_id_token("not-a-real-token")


# -- NEW-2: signed SAML assertion cannot be replayed in a fresh response ------

async def test_signed_assertion_replay_in_fresh_response_rejected():
    import test_saml as ts
    from tessera.cache.memory_cache import InMemoryCache
    from tessera.db.memory import InMemoryDatabase

    db = InMemoryDatabase()
    await db.connect()
    cache = InMemoryCache()
    config = ts.SAMLConfig(
        sp_entity_id=ts.SP_ENTITY_ID,
        acs_url=ts.ACS_URL,
        slo_url=ts.SLO_URL,
        idp_entity_id=ts.IDP_ENTITY_ID,
        idp_sso_url=ts.IDP_SSO_URL,
        idp_certificate=ts.IDP_CERT,
    )
    manager = ts.SAMLManager(config, db, cache)

    request_id_1 = await ts._start(manager)
    response_1 = ts._signed_response_b64(
        response_id="_resp_A", in_response_to=request_id_1, assertion_id="_assert_X"
    )
    result = await manager.validate_response(response_1, relay_state="rs")
    assert result["name_id"]

    # Attacker re-wraps the SAME signed assertion in a fresh Response with a
    # new response id and a fresh outstanding AuthnRequest.
    request_id_2 = await ts._start(manager)
    response_2 = ts._signed_response_b64(
        response_id="_resp_B", in_response_to=request_id_2, assertion_id="_assert_X"
    )
    with pytest.raises(ValueError, match="already consumed"):
        await manager.validate_response(response_2, relay_state="rs")


# -- NEW-3: social login never links accounts by display name -----------------

async def test_social_login_does_not_link_by_display_name(social, db) -> None:
    from test_social import _StubGitHub

    # Victim account whose USERNAME equals the attacker-controlled provider
    # display name. Pre-fix, the login linked into this account by username;
    # with auto_create_users=False and an UNVERIFIED provider email the
    # hardened code must refuse with user_not_found (no link, no creation).
    existing = await db.create_user(
        {
            "username": "GitHub User",
            "email": "victim@example.com",
            "hashed_password": "x",
        }
    )
    social.github_manager = _StubGitHub(
        "attacker@evil.example", verified=False, name="GitHub User"
    )
    with pytest.raises(AuthenticationError) as exc:
        await social.github_social_login("code-name-link")
    assert exc.value.code == "user_not_found"
    # The victim account is untouched and was never returned.
    assert (await db.get_user_by_id(existing["id"]))["username"] == "GitHub User"


# -- NEW-8: Apple social login validates CSRF state ---------------------------

async def test_apple_social_login_rejects_state_mismatch(social) -> None:
    social.apple_manager = object()  # never reached: state check comes first
    with pytest.raises(AuthenticationError) as exc:
        await social.apple_social_login(
            "https://app/callback", code="c", state="attacker", expected_state="real"
        )
    assert exc.value.code == "oauth_state_mismatch"
