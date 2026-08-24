"""Traditional auth flow on MongoDB + Redis.

Requires a running MongoDB and Redis, plus extras:

    pip install "tessera[mongodb]"

Environment variables (no secrets are hardcoded):

    TESSERA_JWT_SECRET      JWT signing secret (generate: python -c \\
                          "import secrets; print(secrets.token_urlsafe(48))")
    TESSERA_DB_URL          e.g. mongodb://localhost:27017
    TESSERA_DB_NAME         MongoDB database name, e.g. tessera_db
    TESSERA_REDIS_URL       e.g. redis://localhost:6379
    TESSERA_EMAIL_ENABLED   optional; "true" to exercise the password-reset email

The demo password is generated per run; real applications collect
passwords from users over a secure channel. The MongoDB adapter creates
its own contract collections + indexes on connect (CONTRACTS.md §4).
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

from tessera.cache.redis_cache import RedisCache     # noqa: E402
from tessera.config import AuthConfig                # noqa: E402
from tessera.core.auth_manager import (              # noqa: E402
    TraditionalAuthManager,
)
from tessera.db.mongodb import MongoDB               # noqa: E402
from tessera.errors import TesseraError                # noqa: E402
from tessera.mfa.mfa_setup import MFAAuthManager     # noqa: E402
from tessera.utils.security import SecurityManager   # noqa: E402

DEMO_PASSWORD = secrets.token_urlsafe(16)
DEMO_USERNAME = "janedoe"
DEMO_EMAIL = "jane@example.com"


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
        security = SecurityManager(db=db, cache=cache, config=config)
        mfa = MFAAuthManager(db=db, cache=cache, config=config)
        auth = TraditionalAuthManager(
            db=db,
            config=config,
            cache=cache,
            mfa_manager=mfa,
            security_manager=security,
        )

        # 1. Register.
        try:
            response = await auth.register_user(
                username=DEMO_USERNAME, email=DEMO_EMAIL, password=DEMO_PASSWORD
            )
            print("MongoDB registration:", response.get("message", response))
        except TesseraError as exc:
            print("MongoDB registration error:", exc)

        # 2. Login -> {"access_token", "refresh_token"}.
        tokens = await auth.login_user(
            username=DEMO_USERNAME, password=DEMO_PASSWORD
        )
        print("MongoDB login: received access + refresh tokens")

        # 3. Refresh (rotates the pair; the old refresh token is invalidated).
        new_tokens = await auth.refresh_token(refresh_token=tokens["refresh_token"])
        print("MongoDB refresh: rotated token pair")

        # 4. Logout.
        await auth.logout_user(access_token=new_tokens["access_token"])
        print("MongoDB logout: session revoked")

        # 5. MFA enrollment: begin -> confirm with a real TOTP code.
        pending = await auth.enable_mfa(username=DEMO_USERNAME)
        print(
            "MFA enrollment started; render otpauth_url as a QR code:",
            pending.get("otpauth_url", ""),
        )
        try:
            import pyotp

            code = pyotp.TOTP(pending["mfa_secret"]).now()
            confirmed = await auth.confirm_mfa(code, username=DEMO_USERNAME)
            print("MFA confirmed:", confirmed.get("message", confirmed))
        except ImportError:
            print("pyotp not installed; skipping MFA confirmation")

        # 6. Password reset (only when an email provider is configured).
        if os.environ.get("TESSERA_EMAIL_ENABLED", "").lower() == "true":
            await auth.request_password_reset(email=DEMO_EMAIL)
            print("Password reset email requested (token delivered by email only)")
        else:
            print("Skipping password reset (set TESSERA_EMAIL_ENABLED=true to try it)")
    finally:
        await cache.close()
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
