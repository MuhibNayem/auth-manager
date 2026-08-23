"""Zero-service quick start: register -> login -> refresh -> logout.

Runs end-to-end on the built-in in-memory fakes (CONTRACTS.md §4
``InMemoryDatabase``, §3 ``InMemoryCache``) — no database, Redis, or
network access required. Useful as a smoke test of an installation:

    pip install "authy-package[dev]"
    python examples/example_memory_quickstart.py

Token semantics demonstrated (CONTRACTS.md §6):
- tokens are returned as ``{"access_token": ..., "refresh_token": ...}``;
- refresh tokens ROTATE on use: the old refresh token is invalidated,
  so replaying it must fail;
- logout revokes the session behind the access token.

The JWT secret below is generated per-process for the demo. Real
deployments must set ``AUTHY_JWT_SECRET`` explicitly (§2: validate()
rejects empty/placeholder secrets, and production refuses placeholders).

Status gate (2.0 remediation): this example is written against the
intended public API (``authy_package.core.auth_manager``). Config load +
validation, the in-memory fakes, and registration run today; the
login/refresh/logout steps are verified once the core auth manager
completes its migration to CONTRACTS.md §3/§6 (see
docs/REMEDIATION_STATUS_packaging.md, pending-core-migration).
"""

import asyncio
import os
import secrets

# --- Environment configuration (read by AuthConfig.from_env) --------------
# Generate a strong per-run secret for this demo when none is provided.
os.environ.setdefault("AUTHY_JWT_SECRET", secrets.token_urlsafe(48))
os.environ.setdefault("AUTHY_ENV", "development")
os.environ.setdefault("AUTHY_DB_TYPE", "memory")

from authy_package.config import AuthConfig                          # noqa: E402
from authy_package.core.auth_manager import TraditionalAuthManager  # noqa: E402
from authy_package.cache.memory_cache import InMemoryCache          # noqa: E402
from authy_package.db.memory import InMemoryDatabase                # noqa: E402
from authy_package.errors import AuthyError                         # noqa: E402
from authy_package.mfa.mfa_setup import MFAAuthManager              # noqa: E402
from authy_package.utils.security import SecurityManager            # noqa: E402

# A strong throwaway password for the demo account (never hardcode one).
DEMO_PASSWORD = secrets.token_urlsafe(16)
DEMO_USERNAME = "janedoe"
DEMO_EMAIL = "jane@example.com"


async def main() -> None:
    # 1. Configuration from environment, validated per CONTRACTS.md §2.
    config = AuthConfig.from_env()
    config.validate()
    print(f"[config] env={config.env} db_type={config.database.db_type}")

    # 2. In-memory fakes implement the full async db/cache contracts.
    db = InMemoryDatabase()
    cache = InMemoryCache()
    await db.connect()

    try:
        security = SecurityManager(db=db, cache=cache, config=config)
        mfa = MFAAuthManager(db=db)
        auth = TraditionalAuthManager(
            db=db, cache=cache, mfa_manager=mfa, security_manager=security
        )

        # 3. Register.
        registered = await auth.register_user(
            username=DEMO_USERNAME, email=DEMO_EMAIL, password=DEMO_PASSWORD
        )
        print("[register] ok:", registered.get("message", registered))

        # 4. Login -> {"access_token", "refresh_token"}.
        tokens = await auth.login_user(
            username=DEMO_USERNAME, password=DEMO_PASSWORD
        )
        assert "access_token" in tokens and "refresh_token" in tokens, tokens
        print("[login] ok: received access + refresh tokens")

        # 5. Refresh rotation: the new pair replaces the old one.
        new_tokens = await auth.refresh_token(refresh_token=tokens["refresh_token"])
        assert "access_token" in new_tokens and "refresh_token" in new_tokens
        print("[refresh] ok: rotated token pair")

        # 6. Replaying the OLD refresh token must fail (CONTRACTS.md §3.1).
        try:
            await auth.refresh_token(refresh_token=tokens["refresh_token"])
        except AuthyError as exc:
            print(f"[refresh-replay] correctly rejected: {exc}")
        else:
            raise AssertionError("old refresh token was accepted after rotation")

        # 7. Logout revokes the session behind the access token.
        await auth.logout_user(
            access_token=new_tokens["access_token"], username=DEMO_USERNAME
        )
        print("[logout] ok: session revoked")

        print("quick start completed successfully")
    finally:
        await cache.close()
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
