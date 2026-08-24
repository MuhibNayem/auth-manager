"""TOTP multi-factor authentication (CONTRACTS.md §0, §6).

Security properties:

- Enabling MFA is a two-step flow: :meth:`MFAAuthManager.setup_mfa` issues a
  *pending* secret, and MFA is only activated by
  :meth:`MFAAuthManager.confirm_mfa` after the user proves possession of the
  secret by submitting a valid TOTP code.
- Verification attempts (both confirmation and login) are rate limited with
  cache counters (§3.1 ``authy:ratelimit:mfa:{user_id}``).
- Code comparison relies on ``pyotp``'s verify semantics, which compare in
  constant time (``hmac.compare_digest``).
- Eight single-use backup codes are generated at activation; only their
  sha256 digests are stored, and each code is deleted on first use.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from authy_package.cache.abstract_cache import AbstractCache
from authy_package.config import AuthConfig
from authy_package.db.abstract_db import AbstractDatabase
from authy_package.errors import AuthenticationError, ConfigError, RateLimitError

logger = logging.getLogger("authy.mfa")

__all__ = ["MFAAuthManager"]

#: Cache key holding a pending (unconfirmed) TOTP secret (§3.1 style).
PENDING_SECRET_KEY_TEMPLATE = "authy:mfa:pending:{user_id}"

#: Cache key for MFA attempt counters (§3.1 ratelimit namespace).
MFA_RATE_LIMIT_KEY_TEMPLATE = "authy:ratelimit:mfa:{user_id}"

#: Pending secrets expire if never confirmed.
PENDING_SECRET_TTL_SECONDS = 600

#: Defaults when no AuthConfig is supplied.
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_WINDOW_SECONDS = 300

#: Number of single-use backup codes issued at activation.
BACKUP_CODE_COUNT = 8


def _lazy_pyotp():
    """Import ``pyotp`` lazily (§0.9) with an informative error."""
    try:
        import pyotp
    except ImportError as exc:  # pragma: no cover - exercised w/o extra
        raise ImportError(
            "MFA requires the 'pyotp' package; install authy-package with "
            "the corresponding extra"
        ) from exc
    return pyotp


def _hash_backup_code(code: str) -> str:
    """Backup codes are stored only as sha256 hex digests."""
    return hashlib.sha256(code.strip().lower().encode("utf-8")).hexdigest()


class MFAAuthManager:
    """TOTP MFA manager on the db/cache contracts (CONTRACTS.md §4, §3).

    Args:
        db: Database adapter implementing the §4 contract.
        cache: Cache adapter implementing the §3 contract (required: pending
            secrets and attempt counters live in the cache).
        config: Optional :class:`AuthConfig`; used for rate-limit settings
            and the provisioning-URI issuer name.
    """

    def __init__(
        self,
        db: AbstractDatabase,
        cache: AbstractCache,
        config: Optional[AuthConfig] = None,
    ) -> None:
        if db is None:
            raise ConfigError("MFAAuthManager requires a database adapter")
        if cache is None:
            raise ConfigError("MFAAuthManager requires a cache adapter")
        self.db = db
        self.cache = cache
        self.config = config
        if config is not None:
            self._max_attempts = config.rate_limit_max_attempts
            self._window_seconds = config.rate_limit_window_seconds
            self._issuer_name = config.app_name or "Authy"
        else:
            self._max_attempts = DEFAULT_MAX_ATTEMPTS
            self._window_seconds = DEFAULT_WINDOW_SECONDS
            self._issuer_name = "Authy"

    # -- helpers -------------------------------------------------------------

    async def _get_user_or_raise(
        self,
        username: Optional[str],
        email: Optional[str],
        phone: Optional[str],
    ) -> Dict[str, Any]:
        """Fetch one user by identifier; identical error when missing."""
        if not any((username, email, phone)):
            raise ValueError("At least one of username, email or phone is required")
        user = await self.db.get_user_by_identifier(
            username=username, email=email, phone=phone
        )
        if user is None:
            raise AuthenticationError("Invalid credentials", code="authentication_failed")
        return user

    async def _check_attempt_budget(self, user_id: str) -> None:
        """Raise when the MFA attempt budget for the window is exhausted."""
        key = MFA_RATE_LIMIT_KEY_TEMPLATE.format(user_id=user_id)
        raw = await self.cache.get(key)
        attempts = int(raw) if raw is not None else 0
        if attempts >= self._max_attempts:
            remaining = await self.cache.ttl(key)
            if remaining < 0:
                await self.cache.expire(key, self._window_seconds)
                remaining = self._window_seconds
            raise RateLimitError(
                "Too many MFA attempts; please try again later",
                retry_after=max(1, remaining),
                code="mfa_rate_limited",
            )

    async def _record_failed_attempt(self, user_id: str) -> None:
        """Count a failed MFA attempt against the fixed window."""
        key = MFA_RATE_LIMIT_KEY_TEMPLATE.format(user_id=user_id)
        attempts = await self.cache.incr(key)
        if attempts == 1 or await self.cache.ttl(key) == -1:
            await self.cache.expire(key, self._window_seconds)

    async def _clear_attempts(self, user_id: str) -> None:
        await self.cache.delete(MFA_RATE_LIMIT_KEY_TEMPLATE.format(user_id=user_id))

    def _pending_key(self, user_id: str) -> str:
        return PENDING_SECRET_KEY_TEMPLATE.format(user_id=user_id)

    async def _store_pending_secret(self, user_id: str, secret: str) -> None:
        import json

        await self.cache.set(
            self._pending_key(user_id),
            json.dumps(
                {
                    "secret": secret,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            ),
            ttl_seconds=PENDING_SECRET_TTL_SECONDS,
        )

    async def _peek_pending_secret(self, user_id: str) -> Optional[str]:
        """Read the pending secret without consuming it."""
        import json

        raw = await self.cache.get(self._pending_key(user_id))
        if raw is None:
            return None
        try:
            return str(json.loads(raw).get("secret")) or None
        except (TypeError, ValueError):
            return None

    async def _take_pending_secret(self, user_id: str) -> Optional[str]:
        """Fetch-and-delete the pending secret (single consumption)."""
        secret = await self._peek_pending_secret(user_id)
        if secret is not None:
            await self.cache.delete(self._pending_key(user_id))
        return secret

    async def _begin_setup(
        self,
        username: Optional[str],
        email: Optional[str],
        phone: Optional[str],
    ) -> Dict[str, Any]:
        """Shared setup body for first-time setup and reconfiguration."""
        pyotp = _lazy_pyotp()
        user = await self._get_user_or_raise(username, email, phone)
        user_id = str(user["id"])
        identifier = user.get("email") or user.get("username") or user.get("phone") or user_id

        mfa_secret = pyotp.random_base32()
        await self._store_pending_secret(user_id, mfa_secret)

        otpauth_url = pyotp.TOTP(mfa_secret).provisioning_uri(
            name=str(identifier), issuer_name=self._issuer_name
        )
        logger.info("MFA setup started for user %s (pending confirmation)", user_id)
        return {
            "message": "Scan the QR code / store the secret, then confirm with a code.",
            "mfa_secret": mfa_secret,
            "otpauth_url": otpauth_url,
            "pending": True,
        }

    # -- setup / confirm -------------------------------------------------------

    async def setup_mfa(
        self,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Start MFA enrollment; returns a *pending* secret and OTPAuth URL.

        MFA is NOT enabled until :meth:`confirm_mfa` succeeds with a valid
        TOTP code for the returned secret.
        """
        user = await self._get_user_or_raise(username, email, phone)
        if user.get("mfa_enabled"):
            raise AuthenticationError(
                "MFA is already enabled; use reconfigure_mfa to rotate",
                code="mfa_already_enabled",
            )
        return await self._begin_setup(username, email, phone)

    async def reconfigure_mfa(
        self,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Rotate the TOTP secret for a user who already has MFA enabled.

        The old secret stays active until :meth:`confirm_mfa` swaps in the
        new one, so users are never locked out mid-rotation.
        """
        user = await self._get_user_or_raise(username, email, phone)
        if not user.get("mfa_enabled"):
            raise AuthenticationError(
                "MFA is not enabled for this user", code="mfa_not_enabled"
            )
        return await self._begin_setup(username, email, phone)

    async def confirm_mfa(
        self,
        code: str,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Confirm a pending setup with a TOTP code and activate MFA.

        Returns the one-time plaintext backup codes; only their sha256
        digests are persisted.

        Raises:
            AuthenticationError: When no setup is pending or the code is
                invalid.
            RateLimitError: When the confirmation attempt budget is spent.
        """
        pyotp = _lazy_pyotp()
        if not code or not isinstance(code, str):
            raise ValueError("code must be a non-empty string")
        user = await self._get_user_or_raise(username, email, phone)
        user_id = str(user["id"])

        await self._check_attempt_budget(user_id)
        pending_secret = await self._peek_pending_secret(user_id)
        if not pending_secret:
            raise AuthenticationError(
                "No pending MFA setup; call setup_mfa first", code="mfa_setup_pending_missing"
            )

        if not pyotp.TOTP(pending_secret).verify(code, valid_window=1):
            # Keep the pending secret so the user can retry within the
            # attempt budget; the counter provides the rate limit.
            await self._record_failed_attempt(user_id)
            raise AuthenticationError("Invalid MFA code", code="mfa_code_invalid")

        await self.cache.delete(self._pending_key(user_id))

        backup_codes = [secrets.token_hex(4) for _ in range(BACKUP_CODE_COUNT)]
        updates: Dict[str, Any] = {
            "mfa_enabled": True,
            "mfa_secret": pending_secret,
            "mfa_backup_codes": [_hash_backup_code(c) for c in backup_codes],
            "mfa_confirmed_at": datetime.now(timezone.utc).isoformat(),
        }
        await self.db.update_user(user_id, updates)
        await self._clear_attempts(user_id)
        logger.info("MFA enabled for user %s", user_id)
        return {
            "message": "MFA has been enabled successfully.",
            "backup_codes": backup_codes,
        }

    # -- verification ------------------------------------------------------------

    async def verify_mfa_code(
        self,
        mfa_code: str,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> bool:
        """Verify a TOTP code for a user with MFA enabled.

        Raises:
            AuthenticationError: When MFA is not enabled, or the code is
                invalid.
            RateLimitError: When the attempt budget for the window is spent.
        """
        pyotp = _lazy_pyotp()
        if not mfa_code or not isinstance(mfa_code, str):
            raise ValueError("mfa_code must be a non-empty string")
        user = await self._get_user_or_raise(username, email, phone)
        user_id = str(user["id"])

        if not user.get("mfa_enabled") or not user.get("mfa_secret"):
            raise AuthenticationError("MFA is not enabled for this user", code="mfa_not_enabled")

        await self._check_attempt_budget(user_id)
        if not pyotp.TOTP(str(user["mfa_secret"])).verify(mfa_code, valid_window=1):
            await self._record_failed_attempt(user_id)
            raise AuthenticationError("Invalid MFA code", code="mfa_code_invalid")

        await self._clear_attempts(user_id)
        return True

    async def use_backup_code(
        self,
        code: str,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> bool:
        """Consume a single-use backup code.

        Codes are compared against stored sha256 digests; a consumed code is
        removed immediately so it can never be replayed.
        """
        if not code or not isinstance(code, str):
            raise ValueError("code must be a non-empty string")
        user = await self._get_user_or_raise(username, email, phone)
        user_id = str(user["id"])

        if not user.get("mfa_enabled"):
            raise AuthenticationError("MFA is not enabled for this user", code="mfa_not_enabled")

        await self._check_attempt_budget(user_id)
        stored: List[str] = list(user.get("mfa_backup_codes") or [])
        candidate = _hash_backup_code(code)
        if candidate not in stored:
            await self._record_failed_attempt(user_id)
            raise AuthenticationError("Invalid backup code", code="mfa_backup_code_invalid")

        stored.remove(candidate)
        await self.db.update_user(user_id, {"mfa_backup_codes": stored})
        await self._clear_attempts(user_id)
        logger.info("Backup code consumed for user %s (%d remaining)", user_id, len(stored))
        return True
