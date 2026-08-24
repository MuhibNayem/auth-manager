"""Traditional auth flow on a SQL database + Redis.

Requires a running SQL database and Redis, plus extras:

    pip install "tessera[postgresql]"   # or [all]

Works with any SQLAlchemy async URL; SQLite (aiosqlite) is fine for a
local trial:

    TESSERA_DB_URL=sqlite+aiosqlite:///./tessera_demo.db

Environment variables (no secrets are hardcoded):

    TESSERA_JWT_SECRET    JWT signing secret (generate: python -c \\
                        "import secrets; print(secrets.token_urlsafe(48))")
    TESSERA_DB_URL        e.g. postgresql+asyncpg://<user>:<pass>@localhost:5432/tessera
    TESSERA_REDIS_URL     e.g. redis://localhost:6379
    TESSERA_EMAIL_ENABLED optional; "true" to exercise the password-reset email
    MAILJET_API_KEY / MAILJET_API_SECRET   when email is enabled

The demo password is generated per run; real applications collect
passwords from users over a secure channel. The SQL adapter creates its
own contract tables on connect (CONTRACTS.md §4) — no ORM models are
supplied by the application.
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
os.environ.setdefault("TESSERA_DB_TYPE", "sql")

from tessera.cache.redis_cache import RedisCache     # noqa: E402
from tessera.config import AuthConfig                # noqa: E402
from tessera.core.auth_manager import (              # noqa: E402
    TraditionalAuthManager,
)
from tessera.db.sql import SQLDatabase               # noqa: E402
from tessera.errors import TesseraError                # noqa: E402
from tessera.mfa.mfa_setup import MFAAuthManager     # noqa: E402
from tessera.utils.security import SecurityManager   # noqa: E402

DEMO_PASSWORD = secrets.token_urlsafe(16)
DEMO_USERNAME = "janedoe"
DEMO_EMAIL = "jane@example.com"


async def main() -> None:
    config = AuthConfig.from_env()
    config.validate()

    db = SQLDatabase(os.environ["TESSERA_DB_URL"])
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
            print("SQL registration:", response.get("message", response))
        except TesseraError as exc:
            print("SQL registration error:", exc)

        # 2. Login -> {"access_token", "refresh_token"}.
        tokens = await auth.login_user(
            username=DEMO_USERNAME, password=DEMO_PASSWORD
        )
        print("SQL login: received access + refresh tokens")

        # 3. Refresh (rotates the pair; the old refresh token is invalidated).
        new_tokens = await auth.refresh_token(refresh_token=tokens["refresh_token"])
        print("SQL refresh: rotated token pair")

        # 4. Logout.
        await auth.logout_user(access_token=new_tokens["access_token"])
        print("SQL logout: session revoked")

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
