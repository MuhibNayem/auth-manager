"""Social OAuth login flows (Google, GitHub, Facebook, Apple).

Requires MongoDB + Redis and provider credentials, all from the
environment (nothing hardcoded):

    pip install "tessera[mongodb]"

    TESSERA_JWT_SECRET / TESSERA_DB_URL / TESSERA_DB_NAME / TESSERA_REDIS_URL

    GOOGLE_CLIENT_SECRETS_FILE   OAuth client-secrets JSON path
    GOOGLE_REDIRECT_URI          e.g. https://app.example.com/auth/google/callback
    GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET / GITHUB_REDIRECT_URI
    FACEBOOK_APP_ID / FACEBOOK_APP_SECRET / FACEBOOK_REDIRECT_URI
    APPLE_CLIENT_ID / APPLE_TEAM_ID / APPLE_KEY_ID / APPLE_PRIVATE_KEY_PATH

Authorization codes arrive from your frontend callback; pass the one you
want to exercise via the matching env var:

    TESSERA_GOOGLE_CODE / TESSERA_GITHUB_CODE / TESSERA_FACEBOOK_CODE / TESSERA_APPLE_CODE

Every block that lacks configuration is skipped with a clear message —
there is no pseudocode in this example. Accounts are only linked to
existing users when the provider reports a VERIFIED email
(CONTRACTS.md remediation: unverified emails cannot take over accounts).
"""

import asyncio
import os
import secrets
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

os.environ.setdefault("TESSERA_JWT_SECRET", secrets.token_urlsafe(48))
os.environ.setdefault("TESSERA_ENV", "development")
os.environ.setdefault("TESSERA_DB_TYPE", "mongodb")

from tessera.cache.redis_cache import RedisCache    # noqa: E402
from tessera.config import AuthConfig               # noqa: E402
from tessera.core.auth_manager import (             # noqa: E402
    SocialAuthManager,
)
from tessera.db.mongodb import MongoDB              # noqa: E402
from tessera.errors import TesseraError               # noqa: E402
from tessera.mfa.mfa_setup import MFAAuthManager    # noqa: E402
from tessera.social.apple import AppleManager       # noqa: E402
from tessera.social.facebook import FacebookManager  # noqa: E402
from tessera.social.github import GitHubManager     # noqa: E402
from tessera.social.google import GoogleManager     # noqa: E402


def build_providers() -> dict:
    """Instantiate only the providers whose credentials are configured."""
    providers: dict = {}

    secrets_file = os.environ.get("GOOGLE_CLIENT_SECRETS_FILE")
    google_redirect = os.environ.get("GOOGLE_REDIRECT_URI")
    if secrets_file and google_redirect:
        providers["google"] = GoogleManager(
            secrets_file, google_redirect, ["openid", "email", "profile"]
        )

    if os.environ.get("GITHUB_CLIENT_ID") and os.environ.get("GITHUB_CLIENT_SECRET"):
        providers["github"] = GitHubManager(
            os.environ["GITHUB_CLIENT_ID"],
            os.environ["GITHUB_CLIENT_SECRET"],
            os.environ.get("GITHUB_REDIRECT_URI", ""),
        )

    if os.environ.get("FACEBOOK_APP_ID") and os.environ.get("FACEBOOK_APP_SECRET"):
        providers["facebook"] = FacebookManager(
            os.environ["FACEBOOK_APP_ID"],
            os.environ["FACEBOOK_APP_SECRET"],
            os.environ.get("FACEBOOK_REDIRECT_URI", ""),
        )

    apple_key_path = os.environ.get("APPLE_PRIVATE_KEY_PATH")
    if (
        os.environ.get("APPLE_CLIENT_ID")
        and os.environ.get("APPLE_TEAM_ID")
        and os.environ.get("APPLE_KEY_ID")
        and apple_key_path
    ):
        with open(apple_key_path, encoding="utf-8") as fh:
            private_key = fh.read()
        providers["apple"] = AppleManager(
            os.environ["APPLE_CLIENT_ID"],
            os.environ["APPLE_TEAM_ID"],
            os.environ["APPLE_KEY_ID"],
            private_key,
        )

    return providers


async def run_login(auth_manager: SocialAuthManager, provider: str, code: str) -> dict | None:
    """Exchange one provider's authorization code; return the login response."""
    try:
        if provider == "google":
            response = await auth_manager.google_social_login(code)
        elif provider == "github":
            response = await auth_manager.github_social_login(code)
        elif provider == "facebook":
            response = await auth_manager.facebook_social_login(code)
        elif provider == "apple":
            redirect_uri = os.environ.get("APPLE_REDIRECT_URI", "")
            response = await auth_manager.apple_social_login(redirect_uri, code=code)
        else:
            return None
        print(f"{provider} login: user={response['user'].get('email')}")
        return response
    except TesseraError as exc:
        print(f"{provider} login error: {exc}")
        return None


async def main() -> None:
    config = AuthConfig.from_env()
    config.validate()

    db = MongoDB(
        {
            "url": os.environ["TESSERA_DB_URL"],
            "db_name": os.environ.get("TESSERA_DB_NAME", "tessera_db"),
        }
    )
    cache = RedisCache(os.environ.get("TESSERA_REDIS_URL", "redis://localhost:6379"))
    await db.connect()

    try:
        providers = build_providers()
        auth_manager = SocialAuthManager(
            db=db,
            config=config,
            cache=cache,
            google_manager=providers.get("google"),
            github_manager=providers.get("github"),
            facebook_manager=providers.get("facebook"),
            apple_manager=providers.get("apple"),
            mfa_manager=MFAAuthManager(db=db, cache=cache, config=config),
        )

        if not providers:
            print("No social providers configured; set their env vars (see docstring).")
            return

        # Exchange whichever authorization codes were provided.
        login_response: dict | None = None
        for provider in ("google", "github", "facebook", "apple"):
            if provider not in providers:
                print(f"[skip] {provider}: credentials not configured")
                continue
            code = os.environ.get(f"TESSERA_{provider.upper()}_CODE")
            if not code:
                print(f"[skip] {provider}: no TESSERA_{provider.upper()}_CODE to exchange")
                continue
            login_response = await run_login(auth_manager, provider, code) or login_response

        if login_response is None:
            print("No login performed; nothing to refresh or log out.")
            return

        # Use a REAL identifier from the authenticated user (the previous
        # version of this example contained `'email' or 'username' or 'phone'`
        # pseudocode, which always evaluated to 'email').
        user = login_response["user"]
        user_identifier = user.get("email") or user.get("username")

        # Refresh the provider access token when the login returned one.
        token_info = login_response.get("access_token") or {}
        provider_refresh = token_info.get("refresh_token")
        if provider_refresh:
            try:
                refreshed = await auth_manager.refresh_access_token(
                    provider="google", refresh_token=provider_refresh, user=user
                )
                print("Provider token refreshed:", sorted(refreshed.keys()))
            except TesseraError as exc:
                print("Provider token refresh error:", exc)

        # Enroll MFA for the social user: begin -> confirm with a real code.
        try:
            pending = await auth_manager.enable_mfa(email=user_identifier)
            import pyotp

            code = pyotp.TOTP(pending["mfa_secret"]).now()
            confirmed = await auth_manager.confirm_mfa(code, email=user_identifier)
            print("MFA confirmed for", user_identifier, "-", confirmed.get("message"))
        except TesseraError as exc:
            print("MFA error:", exc)

        # Logout (revokes provider tokens where supported).
        await auth_manager.logout(provider="google", user=user)
        print("User logged out:", user_identifier)
    finally:
        await cache.close()
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
