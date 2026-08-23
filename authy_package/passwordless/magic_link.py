"""Passwordless authentication via magic links (CONTRACTS.md §3.1).

Security properties:

- Tokens are ``secrets.token_urlsafe(32)`` (256 bits of entropy) and live
  only in the cache under ``authy:magiclink:{token}`` with
  ``config.magic_link_ttl_seconds`` as TTL.
- Verification is **single-use**: the record is fetched (``get_json``) and
  deleted before any side effect; a missing record is treated as
  consumed/expired.
- ``redirect_url`` is validated against the host of
  ``config.default_redirect_url`` or ``config.base_url`` — anything else is
  rejected (no open redirect).
- Sending is rate limited via cache counters
  (``authy:ratelimit:magiclink:{email}``).
- Users are auto-created only when ``config.auto_create_users`` is set.
- All events go through the db audit contract (``save_audit_event``).
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from authy_package.cache.abstract_cache import AbstractCache
from authy_package.config import AuthConfig
from authy_package.db.abstract_db import AbstractDatabase
from authy_package.errors import AuthenticationError, ConfigError, RateLimitError

logger = logging.getLogger("authy.passwordless.magic_link")

__all__ = ["MagicLinkManager"]

#: §3.1 cache key schema.
MAGIC_LINK_KEY_TEMPLATE = "authy:magiclink:{token}"
SEND_RATE_KEY_TEMPLATE = "authy:ratelimit:magiclink:{email}"

#: Send rate limit defaults (fixed window).
DEFAULT_MAX_SENDS_PER_WINDOW = 3
DEFAULT_SEND_WINDOW_SECONDS = 300


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MagicLinkManager:
    """Magic-link passwordless login on the cache/db contracts.

    Args:
        config: Canonical :class:`AuthConfig` (TTL, base_url, redirect
            allow-list, auto_create_users).
        db: Database adapter (§4) for users and audit events.
        cache: Cache adapter (§3) holding the single-use tokens.
        email_service: Optional duck-typed sender exposing
            ``async send_magic_link_email(to=..., magic_link=...,
            expires_in_minutes=...)``. When omitted, sending is a logged
            no-op so development and tests never need network.
    """

    def __init__(
        self,
        config: AuthConfig,
        db: AbstractDatabase,
        cache: AbstractCache,
        email_service: Any = None,
    ) -> None:
        if config is None:
            raise ConfigError("MagicLinkManager requires an AuthConfig")
        if db is None:
            raise ConfigError("MagicLinkManager requires a database adapter")
        if cache is None:
            raise ConfigError("MagicLinkManager requires a cache adapter")
        self.config = config
        self.db = db
        self.cache = cache
        self.email_service = email_service

    # -- helpers -------------------------------------------------------------------

    def _allowed_hosts(self) -> set:
        """Hosts permitted for post-login redirects (no open redirect)."""
        hosts = set()
        for url in (self.config.default_redirect_url, self.config.base_url):
            if url:
                host = urlsplit(str(url)).netloc.lower()
                if host:
                    hosts.add(host)
        return hosts

    def _validate_redirect_url(self, redirect_url: Optional[str]) -> Optional[str]:
        """Return a safe redirect URL or raise ``ValueError``."""
        candidate = redirect_url or self.config.default_redirect_url
        if not candidate:
            return None
        parsed = urlsplit(str(candidate))
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"redirect_url must be an absolute http(s) URL: {redirect_url!r}")
        allowed = self._allowed_hosts()
        if allowed and parsed.netloc.lower() not in allowed:
            raise ValueError(
                "redirect_url host is not in the configured allow-list "
                "(default_redirect_url / base_url)"
            )
        return str(candidate)

    async def _check_send_rate_limit(self, email: str) -> None:
        key = SEND_RATE_KEY_TEMPLATE.format(email=email)
        raw = await self.cache.get(key)
        attempts = int(raw) if raw is not None else 0
        if attempts >= DEFAULT_MAX_SENDS_PER_WINDOW:
            remaining = await self.cache.ttl(key)
            if remaining < 0:
                await self.cache.expire(key, DEFAULT_SEND_WINDOW_SECONDS)
                remaining = DEFAULT_SEND_WINDOW_SECONDS
            raise RateLimitError(
                "Too many magic link requests; please try again later",
                retry_after=max(1, remaining),
                code="magic_link_rate_limited",
            )

    async def _record_send(self, email: str) -> None:
        key = SEND_RATE_KEY_TEMPLATE.format(email=email)
        attempts = await self.cache.incr(key)
        if attempts == 1 or await self.cache.ttl(key) == -1:
            await self.cache.expire(key, DEFAULT_SEND_WINDOW_SECONDS)

    async def _audit(
        self, event_type: str, email: Optional[str], metadata: Dict[str, Any]
    ) -> None:
        try:
            await self.db.save_audit_event(
                {
                    "event_type": event_type,
                    "actor": email,
                    "target": email,
                    "metadata": metadata,
                }
            )
        except Exception as exc:  # audit failure must not break the flow
            logger.warning("Audit event %s failed: %s", event_type, exc)

    # -- public API -------------------------------------------------------------------

    async def send_magic_link(
        self,
        email: str,
        redirect_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a single-use magic link and email it.

        Raises:
            ValueError: On a malformed/blocked ``redirect_url`` or missing
                email.
            RateLimitError: When the send budget for the window is spent.
        """
        if not email or not isinstance(email, str):
            raise ValueError("email must be a non-empty string")
        email = email.strip().lower()
        safe_redirect = self._validate_redirect_url(redirect_url)
        await self._check_send_rate_limit(email)

        token = secrets.token_urlsafe(32)
        record = {
            "email": email,
            "redirect_url": safe_redirect,
            "metadata": dict(metadata or {}),
            "created_at": _utcnow().isoformat(),
        }
        await self.cache.set_json(
            MAGIC_LINK_KEY_TEMPLATE.format(token=token),
            record,
            ttl_seconds=self.config.magic_link_ttl_seconds,
        )
        await self._record_send(email)

        magic_link = f"{self.config.base_url.rstrip('/')}/auth/magic?token={token}"
        sent = False
        if self.email_service is not None:
            sent = bool(
                await self.email_service.send_magic_link_email(
                    to=email,
                    magic_link=magic_link,
                    expires_in_minutes=max(
                        1, self.config.magic_link_ttl_seconds // 60
                    ),
                )
            )
        else:
            logger.warning(
                "Email service not configured; magic link for %s not sent", email
            )

        await self._audit("magic_link_sent", email, {"redirect_url": safe_redirect})
        return {"sent": sent, "magic_link": magic_link}

    async def resend_magic_link(self, email: str) -> Dict[str, Any]:
        """Resend a magic link (subject to the send rate limit)."""
        return await self.send_magic_link(email)

    async def verify_magic_link(self, token: str) -> Dict[str, Any]:
        """Consume a magic-link token exactly once and return the user.

        Raises:
            AuthenticationError: When the token is unknown, expired or
                already consumed (missing record == consumed/expired), or
                when no account exists and auto-creation is disabled.
        """
        if not token or not isinstance(token, str):
            raise ValueError("token must be a non-empty string")

        key = MAGIC_LINK_KEY_TEMPLATE.format(token=token)
        record = await self.cache.get_json(key)
        if record is not None:
            # Single-use: delete before acting; the second caller sees a
            # missing record and is rejected below.
            await self.cache.delete(key)
        if record is None:
            await self._audit(
                "magic_link_failed", None, {"reason": "missing_or_consumed"}
            )
            raise AuthenticationError(
                "Magic link is invalid, expired or has already been used",
                code="magic_link_invalid",
            )

        email = str(record.get("email", ""))
        user = await self.db.get_user_by_identifier(email=email) if email else None
        if user is None:
            if self.config.auto_create_users:
                user = await self.db.create_user(
                    {
                        "email": email,
                        "email_verified": True,
                        "auth_method": "magic_link",
                        "mfa_enabled": False,
                    }
                )
                await self._audit("user_created", email, {"method": "magic_link"})
            else:
                await self._audit(
                    "magic_link_failed", email, {"reason": "user_not_found"}
                )
                raise AuthenticationError(
                    "No account exists for this email and automatic account "
                    "creation is disabled",
                    code="user_not_found",
                )

        await self._audit(
            "magic_link_verified", email, {"user_id": str(user.get("id"))}
        )
        return {
            "user": user,
            "redirect_url": record.get("redirect_url"),
            "metadata": record.get("metadata") or {},
        }
