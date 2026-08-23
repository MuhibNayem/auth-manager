"""Traditional auth flow on a SQL database (PostgreSQL) + Redis.

Requires a running PostgreSQL and Redis, plus extras:

    pip install "authy-package[postgresql]"

Environment variables (no secrets are hardcoded):

    AUTHY_JWT_SECRET    JWT signing secret (generate: python -c \\
                        "import secrets; print(secrets.token_urlsafe(48))")
    AUTHY_DB_URL        e.g. postgresql+asyncpg://<user>:<pass>@localhost:5432/authy
    AUTHY_REDIS_URL     e.g. redis://localhost:6379
    AUTHY_EMAIL_ENABLED optional; "true" to exercise the password-reset email
    MAILJET_API_KEY / MAILJET_API_SECRET   when email is enabled

The demo password is generated per run; real applications collect
passwords from users over a secure channel.
"""

import asyncio
import os
import secrets

os.environ.setdefault("AUTHY_JWT_SECRET", secrets.token_urlsafe(48))
os.environ.setdefault("AUTHY_ENV", "development")
os.environ.setdefault("AUTHY_DB_TYPE", "sql")

from sqlalchemy import Boolean, Column, DateTime, String  # noqa: E402
from sqlalchemy.orm import declarative_base                # noqa: E402

from authy_package.cache.redis_cache import RedisCache     # noqa: E402
from authy_package.config import AuthConfig                # noqa: E402
from authy_package.core.auth_manager import (              # noqa: E402
    TraditionalAuthManager,
)
from authy_package.db.sql import SQLDatabase               # noqa: E402
from authy_package.errors import AuthyError                # noqa: E402
from authy_package.mfa.mfa_setup import MFAAuthManager     # noqa: E402
from authy_package.utils.security import SecurityManager   # noqa: E402

DEMO_PASSWORD = secrets.token_urlsafe(16)
DEMO_USERNAME = "janedoe"
DEMO_EMAIL = "jane@example.com"

Base = declarative_base()


class User(Base):
    """ORM model matching the stable user-record keys (CONTRACTS.md §4)."""

    __tablename__ = "users"

    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=True)
    email = Column(String, unique=True, nullable=True)
    phone = Column(String, nullable=True)
    hashed_password = Column(String, nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    role = Column(String, default="user")


async def main() -> None:
    config = AuthConfig.from_env()
    config.validate()

    db = SQLDatabase(os.environ["AUTHY_DB_URL"], orm_model=User)
    cache = RedisCache(os.environ.get("AUTHY_REDIS_URL", "redis://localhost:6379"))
    await db.connect()

    try:
        security = SecurityManager(db=db, cache=cache, config=config)
        mfa = MFAAuthManager(db=db)
        auth = TraditionalAuthManager(
            db=db, cache=cache, mfa_manager=mfa, security_manager=security
        )

        # 1. Register.
        try:
            response = await auth.register_user(
                username=DEMO_USERNAME, email=DEMO_EMAIL, password=DEMO_PASSWORD
            )
            print("SQL registration:", response)
        except AuthyError as exc:
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
        await auth.logout_user(
            access_token=new_tokens["access_token"], username=DEMO_USERNAME
        )
        print("SQL logout: session revoked")

        # 5. MFA setup.
        await auth.enable_mfa(username=DEMO_USERNAME)
        print("MFA enabled; render mfa_secret as an otpauth:// QR code")
        await auth.reconfigure_mfa(username=DEMO_USERNAME)
        print("MFA secret reconfigured")

        # 6. Password reset (only when an email provider is configured).
        if os.environ.get("AUTHY_EMAIL_ENABLED", "").lower() == "true":
            await auth.request_password_reset(
                email=DEMO_EMAIL,
                username=None,
                phone=None,
                sender_email=os.environ.get("AUTHY_SENDER_EMAIL", "noreply@myapp.example"),
                sender_name="Support",
            )
            print("Password reset email requested (token delivered by email only)")
        else:
            print("Skipping password reset (set AUTHY_EMAIL_ENABLED=true to try it)")
    finally:
        await cache.close()
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
