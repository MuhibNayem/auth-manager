"""Zero-service quick start: register -> login -> refresh -> logout.

Runs end-to-end on the built-in in-memory fakes (CONTRACTS.md §4
``InMemoryDatabase``, §3 ``InMemoryCache``) — no database, Redis, or
network access required. Useful as a smoke test of an installation:

    pip install "tessera"
    python examples/example_memory_quickstart.py

Token semantics demonstrated (CONTRACTS.md §6):
- tokens are returned as ``{"access_token": ..., "refresh_token": ...}``;
- refresh tokens ROTATE on use: the old refresh token is invalidated,
  so replaying it must fail;
- logout revokes the session behind the access token.

The JWT secret below is generated per-process for the demo. Real
deployments must set ``TESSERA_JWT_SECRET`` explicitly (§2: validate()
rejects empty/placeholder secrets, and production refuses placeholders).

Verified end-to-end against the 2.0 remediated core auth manager
(``tessera.core.auth_manager`` on CONTRACTS.md §3/§6).
"""

import asyncio
import os
import secrets
import sys
from pathlib import Path

# Allow running directly from a source checkout (``python examples/...``).
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# --- Environment configuration (read by AuthConfig.from_env) --------------
# Generate a strong per-run secret for this demo when none is provided.
os.environ.setdefault("TESSERA_JWT_SECRET", secrets.token_urlsafe(48))
os.environ.setdefault("TESSERA_ENV", "development")
os.environ.setdefault("TESSERA_DB_TYPE", "memory")

from tessera.config import AuthConfig                          # noqa: E402
from tessera.core.auth_manager import TraditionalAuthManager  # noqa: E402
from tessera.cache.memory_cache import InMemoryCache          # noqa: E402
from tessera.db.memory import InMemoryDatabase                # noqa: E402
from tessera.errors import TesseraError                         # noqa: E402
from tessera.mfa.mfa_setup import MFAAuthManager              # noqa: E402
from tessera.utils.security import SecurityManager            # noqa: E402

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
        mfa = MFAAuthManager(db=db, cache=cache, config=config)
        auth = TraditionalAuthManager(
            db=db,
            config=config,
            cache=cache,
            mfa_manager=mfa,
            security_manager=security,
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
        except TesseraError as exc:
            print(f"[refresh-replay] correctly rejected: {exc}")
        else:
            raise AssertionError("old refresh token was accepted after rotation")

        # 7. Logout revokes the session behind the access token.
        await auth.logout_user(access_token=new_tokens["access_token"])
        print("[logout] ok: session revoked")

        print("quick start completed successfully")
    finally:
        await cache.close()
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
