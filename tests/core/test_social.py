"""Social login tests: stray-self regression + unverified-email takeover fix."""

from __future__ import annotations

import hashlib
import hmac as hmac_mod

import pytest

from authy_package.core.auth_manager import SocialAuthManager
from authy_package.errors import AuthenticationError

EXISTING_EMAIL = "taken@example.com"


class _StubGitHub:
    """Duck-typed GitHub provider with controllable verified flag."""

    def __init__(self, email, verified, name="GitHub User"):
        self.email = email
        self.verified = verified
        self.name = name

    def get_access_token(self, code):
        return {"access_token": "gh-token", "token_type": "bearer"}

    def get_user_info(self, token):
        return {"login": "ghuser", "name": self.name, "email": self.email}

    def get_primary_email(self, token):
        return self.email, self.verified


class _StubFacebook:
    def __init__(self, email, verified):
        self.email = email
        self.verified = verified

    def get_access_token(self, code):
        return {"access_token": "fb-short", "expires_in": 3600}

    def get_long_lived_access_token(self, token):
        return {"access_token": "fb-long", "expires_in": 5184000}

    def get_user_info(self, token):
        return {"id": "fbid", "name": "Fb User", "email": self.email,
                "verified": self.verified}


@pytest.fixture
async def existing_user(db):
    return await db.create_user(
        {"email": EXISTING_EMAIL, "username": "taken", "hashed_password": "x"}
    )


# -- regression: these paths previously raised TypeError (stray self) ----------

async def test_github_social_login_runs_without_type_error(social, db):
    social.github_manager = _StubGitHub("fresh@example.com", verified=True)
    result = await social.github_social_login("code-123")
    assert result["message"] == "Login successful."
    assert result["user"]["email"] == "fresh@example.com"
    assert "hashed_password" not in result["user"]


async def test_facebook_social_login_runs_without_type_error(social, db):
    social.facebook_manager = _StubFacebook("fbfresh@example.com", verified=True)
    result = await social.facebook_social_login("code-456")
    assert result["message"] == "Login successful."
    assert result["user"]["email"] == "fbfresh@example.com"


# -- account-takeover protection -------------------------------------------------

async def test_unverified_email_cannot_access_existing_account(social, existing_user):
    social.github_manager = _StubGitHub(EXISTING_EMAIL, verified=False)
    with pytest.raises(AuthenticationError) as exc:
        await social.github_social_login("code")
    assert exc.value.code == "email_unverified"


async def test_verified_email_links_existing_account(social, existing_user):
    social.github_manager = _StubGitHub(EXISTING_EMAIL, verified=True)
    result = await social.github_social_login("code")
    assert result["user"]["id"] == existing_user["id"]


async def test_unverified_email_no_account_no_autocreate_rejected(social):
    social.github_manager = _StubGitHub("newperson@example.com", verified=False)
    with pytest.raises(AuthenticationError) as exc:
        await social.github_social_login("code")
    assert exc.value.code == "user_not_found"


async def test_unverified_email_creates_when_auto_create_enabled(
    make_config, db, cache
):
    config = make_config(auto_create_users=True)
    social = SocialAuthManager(db, config, cache=cache)
    social.github_manager = _StubGitHub("newperson@example.com", verified=False)
    result = await social.github_social_login("code")
    assert result["user"]["email"] == "newperson@example.com"
    assert result["user"]["email_verified"] is False


async def test_facebook_unverified_existing_account_rejected(social, existing_user):
    social.facebook_manager = _StubFacebook(EXISTING_EMAIL, verified=False)
    with pytest.raises(AuthenticationError) as exc:
        await social.facebook_social_login("code")
    assert exc.value.code == "email_unverified"


# -- state (CSRF) -----------------------------------------------------------------

async def test_state_mismatch_rejected(social):
    social.github_manager = _StubGitHub("x@example.com", verified=True)
    with pytest.raises(AuthenticationError) as exc:
        await social.github_social_login(
            "code", state="attacker", expected_state="real-state"
        )
    assert exc.value.code == "oauth_state_mismatch"


# -- provider hardening (real manager logic, no network) ----------------------------

def test_github_authorization_url_has_real_state():
    from authy_package.social.github import GitHubManager

    mgr = GitHubManager("cid", "csecret", "https://app.example.com/cb")
    url, state = mgr.get_authorization_url()
    assert "state=" in url
    assert len(state) >= 16
    assert state not in ("your_custom_state_parameter", "")
    # Different each call
    assert mgr.get_authorization_url()[1] != state


def test_github_validate_state_constant_time():
    from authy_package.social.github import GitHubManager

    assert GitHubManager.validate_state("abc", "abc") is True
    assert GitHubManager.validate_state("abc", "abd") is False
    assert GitHubManager.validate_state(None, "abc") is False


def test_facebook_appsecret_proof_correct():
    from authy_package.social.facebook import FacebookManager

    mgr = FacebookManager("app", "secret", "https://app.example.com/cb")
    expected = hmac_mod.new(
        b"secret", b"the-token", hashlib.sha256
    ).hexdigest()
    assert mgr.appsecret_proof("the-token") == expected


def test_facebook_tokens_not_in_query_string(monkeypatch):
    from authy_package.social import facebook as fb_module

    captured = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {"id": "1", "name": "N", "email": "e@x.com", "verified": True}

    def fake_post(url, data=None, timeout=None):
        captured["url"] = url
        captured["data"] = data
        return _Resp()

    monkeypatch.setattr(fb_module.requests, "post", fake_post)
    mgr = fb_module.FacebookManager("app", "secret", "https://cb")
    mgr.get_user_info("the-access-token")

    # Token must be in the POST body, never in the URL query.
    assert "access_token" not in captured["url"]
    assert captured["data"]["access_token"] == "the-access-token"
    assert "appsecret_proof" in captured["data"]


def test_google_redirect_flow_no_stdin(monkeypatch):
    from authy_package.social.google import GoogleManager

    mgr = GoogleManager("cid", "csecret", "https://app.example.com/cb")
    url, state = mgr.create_authorization_url()
    assert url.startswith("https://accounts.google.com/")
    assert "state=" in url and state
    # exchange_code requires the flow to be established first.
    mgr2 = GoogleManager("cid", "csecret", "https://app.example.com/cb")
    with pytest.raises(ValueError):
        mgr2.exchange_code("code")
