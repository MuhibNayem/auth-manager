"""Advanced session management on the foundation contracts.

Rebuilt per CONTRACTS.md §2/§3/§6:

- Configuration comes from the canonical :class:`AuthConfig` attributes
  (``session_expiry_seconds``, ``max_concurrent_sessions``); JWTs are
  issued/validated through :class:`JWTTokenManager` and the ``type`` claim
  is enforced on every validation.
- Sessions are cached under §3.1 keys (``tessera:session:{session_id}`` and
  ``tessera:user_sessions:{user_id}``) and persisted through the db contract
  (``save_session`` / ``revoke_session`` / ``get_active_sessions``).
- Refresh rotates the session's tokens; the oldest sessions are evicted
  beyond ``max_concurrent_sessions``.
- All timestamps are timezone-aware UTC; last-active updates run as
  background tasks whose references are retained until completion.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from tessera.cache.abstract_cache import AbstractCache
from tessera.config import AuthConfig
from tessera.db.abstract_db import AbstractDatabase
from tessera.errors import AuthenticationError, ConfigError, TokenError
from tessera.utils.security import JWTTokenManager

logger = logging.getLogger("tessera.sessions")

__all__ = ["Session", "SessionManager"]

#: §3.1 cache key schema.
SESSION_KEY_TEMPLATE = "tessera:session:{session_id}"
USER_SESSIONS_KEY_TEMPLATE = "tessera:user_sessions:{user_id}"
REFRESH_MAP_KEY_TEMPLATE = "tessera:session_refresh:{token_hash}"


def _utcnow() -> datetime:
    """Timezone-aware UTC now (§0.5)."""
    return datetime.now(timezone.utc)


def _parse_ts(value: Any) -> datetime:
    """Parse an ISO-8601 timestamp, attaching UTC when naive."""
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass
class Session:
    """An active user session (multi-device aware)."""

    id: str
    user_id: str
    device_id: str
    access_token: str
    refresh_token: str
    created_at: datetime
    expires_at: datetime
    last_active: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_revoked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for cache/db storage (ISO-8601 timestamps)."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "device_id": self.device_id,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "metadata": self.metadata,
            "status": "revoked" if self.is_revoked else "active",
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        """Rebuild a session from its stored representation."""
        return cls(
            id=data["id"],
            user_id=data["user_id"],
            device_id=data.get("device_id", ""),
            access_token=data.get("access_token", ""),
            refresh_token=data.get("refresh_token", ""),
            created_at=_parse_ts(data["created_at"]),
            expires_at=_parse_ts(data["expires_at"]),
            last_active=_parse_ts(data.get("last_active", data["created_at"])),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            metadata=dict(data.get("metadata") or {}),
            is_revoked=data.get("status", "active") != "active"
            or bool(data.get("is_revoked", False)),
        )


class SessionManager:
    """Session lifecycle manager on the cache + db contracts.

    Args:
        config: Canonical :class:`AuthConfig` (session expiry, concurrent
            session limit, JWT settings).
        db: Database adapter (§4) — the durable session store.
        cache: Optional cache adapter (§3) — fast path + user index.
        token_manager: Optional pre-built :class:`JWTTokenManager`.
    """

    def __init__(
        self,
        config: AuthConfig,
        db: AbstractDatabase,
        cache: Optional[AbstractCache] = None,
        token_manager: Optional[JWTTokenManager] = None,
    ) -> None:
        if config is None:
            raise ConfigError("SessionManager requires an AuthConfig")
        if db is None:
            raise ConfigError("SessionManager requires a database adapter")
        self.config = config
        self.db = db
        self.cache = cache
        if token_manager is not None:
            self.token_manager = token_manager
        elif config.jwt_secret:
            self.token_manager = JWTTokenManager(config)
        else:
            raise ConfigError(
                "SessionManager requires config.jwt_secret (JWT token manager)"
            )
        #: Retained references for fire-and-forget last-active tasks (§0).
        self._background_tasks: Set[asyncio.Task] = set()

    # -- public API ------------------------------------------------------------

    async def create_session(
        self,
        user_id: str,
        device_info: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Session:
        """Create a session, persist it, and enforce the concurrency limit."""
        if not user_id or not isinstance(user_id, str):
            raise ValueError("user_id must be a non-empty string")

        session_id = secrets.token_hex(16)
        device_info = dict(device_info or {})
        device_id = str(device_info.get("device_id") or secrets.token_hex(8))
        device_info["device_id"] = device_id

        access_token, refresh_token = self._issue_session_tokens(user_id, session_id)

        now = _utcnow()
        session = Session(
            id=session_id,
            user_id=user_id,
            device_id=device_id,
            access_token=access_token,
            refresh_token=refresh_token,
            created_at=now,
            expires_at=now + timedelta(seconds=self.config.session_expiry_seconds),
            last_active=now,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=device_info,
        )

        await self._store_session(session)
        await self._index_user_session(user_id, session_id)
        await self._enforce_session_limit(user_id)
        logger.info("Created session %s for user %s", session_id, user_id)
        return session

    async def validate_session(self, access_token: str) -> Optional[Session]:
        """Validate an access token and return its active session, if any."""
        try:
            payload = self.token_manager.validate_token(
                access_token, expected_type=JWTTokenManager.ACCESS
            )
        except TokenError:
            return None

        session_id = payload.get("session_id")
        if not session_id:
            return None
        session = await self._get_session(str(session_id))
        if session is None or session.is_revoked:
            return None
        if session.expires_at <= _utcnow():
            return None
        if str(payload.get("sub")) != session.user_id:
            return None

        self._schedule_last_active_update(session.id)
        return session

    async def refresh_session(self, refresh_token: str) -> Optional[Session]:
        """Rotate a session's tokens using its refresh token.

        The old tokens are replaced; a revoked/expired session returns None.
        """
        try:
            payload = self.token_manager.validate_token(
                refresh_token, expected_type=JWTTokenManager.REFRESH
            )
        except TokenError:
            return None

        user_id = payload.get("sub")
        if not user_id:
            return None

        session = await self._resolve_session_for_refresh(refresh_token, str(user_id))
        if session is None or session.is_revoked:
            return None
        if session.expires_at <= _utcnow():
            return None

        # Rotation: the old refresh token stops working immediately.
        if self.cache is not None:
            await self.cache.delete(self._refresh_map_key(refresh_token))

        now = _utcnow()
        session.expires_at = now + timedelta(seconds=self.config.session_expiry_seconds)
        session.last_active = now
        session.access_token, session.refresh_token = self._issue_session_tokens(
            session.user_id, session.id
        )
        await self._store_session(session)
        logger.info("Rotated tokens for session %s", session.id)
        return session

    async def revoke_session(self, session_id: str) -> bool:
        """Revoke one session (atomic status flip in the db)."""
        session = await self._get_session(session_id)
        revoked = await self.db.revoke_session(session_id)
        if session is not None:
            await self._drop_session_state(session.user_id, session_id)
        if revoked:
            logger.info("Revoked session %s", session_id)
        return revoked

    async def revoke_all_user_sessions(self, user_id: str) -> int:
        """Revoke every active session for a user (e.g. password change)."""
        sessions = await self.db.get_active_sessions(user_id)
        revoked = await self.db.revoke_all_user_sessions(user_id)
        for record in sessions:
            await self._drop_session_state(user_id, str(record["id"]))
        return revoked

    async def get_active_sessions(self, user_id: str) -> List[Session]:
        """All active sessions for a user, oldest first."""
        records = await self.db.get_active_sessions(user_id)
        sessions = [Session.from_dict(record) for record in records]
        sessions.sort(key=lambda s: s.created_at)
        return sessions

    # -- internals -----------------------------------------------------------------

    def _issue_session_tokens(self, user_id: str, session_id: str) -> tuple:
        """Issue the session-bound access/refresh JWT pair.

        The access token carries the ``session_id`` claim; the frozen
        ``create_refresh_token`` API takes no extra claims, so the refresh
        token is bound to the session through the
        ``tessera:session_refresh:{sha256(token)}`` cache ledger (with a db
        record fallback when no cache is configured).
        """
        access_token = self.token_manager.create_access_token(
            user_id, additional_claims={"session_id": session_id}
        )
        refresh_token = self.token_manager.create_refresh_token(user_id)
        return access_token, refresh_token

    @staticmethod
    def _refresh_map_key(refresh_token: str) -> str:
        return REFRESH_MAP_KEY_TEMPLATE.format(
            token_hash=hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
        )

    async def _store_session(self, session: Session) -> None:
        """Write-through to cache (§3.1 keys) and db (§4 session methods)."""
        data = session.to_dict()
        if self.cache is not None:
            ttl = max(1, int((session.expires_at - _utcnow()).total_seconds()))
            await self.cache.set_json(
                SESSION_KEY_TEMPLATE.format(session_id=session.id),
                data,
                ttl_seconds=ttl,
            )
        await self.db.save_session(data)
        if self.cache is not None and session.refresh_token:
            ttl = max(1, int((session.expires_at - _utcnow()).total_seconds()))
            await self.cache.set(
                self._refresh_map_key(session.refresh_token),
                session.id,
                ttl_seconds=ttl,
            )

    async def _get_session(self, session_id: str) -> Optional[Session]:
        """Cache-first lookup with db fallback (and re-cache)."""
        if self.cache is not None:
            data = await self.cache.get_json(
                SESSION_KEY_TEMPLATE.format(session_id=session_id)
            )
            if data:
                return Session.from_dict(data)

        data = await self.db.get_session(session_id)
        if not data:
            return None
        session = Session.from_dict(data)
        if self.cache is not None and not session.is_revoked:
            ttl = int((session.expires_at - _utcnow()).total_seconds())
            if ttl > 0:
                await self.cache.set_json(
                    SESSION_KEY_TEMPLATE.format(session_id=session_id),
                    data,
                    ttl_seconds=ttl,
                )
        return session

    async def _index_user_session(self, user_id: str, session_id: str) -> None:
        if self.cache is not None:
            await self.cache.lpush(
                USER_SESSIONS_KEY_TEMPLATE.format(user_id=user_id), session_id
            )

    async def _drop_session_state(self, user_id: str, session_id: str) -> None:
        """Remove cache copies and the user-index entry for one session."""
        if self.cache is None:
            return
        await self.cache.delete(SESSION_KEY_TEMPLATE.format(session_id=session_id))
        record = await self.db.get_session(session_id)
        if record and record.get("refresh_token"):
            await self.cache.delete(self._refresh_map_key(str(record["refresh_token"])))
        index_key = USER_SESSIONS_KEY_TEMPLATE.format(user_id=user_id)
        remaining = [
            sid
            for sid in await self.cache.lrange(index_key, 0, -1)
            if sid != session_id
        ]
        await self.cache.delete(index_key)
        if remaining:
            await self.cache.lpush(index_key, *reversed(remaining))

    async def _enforce_session_limit(self, user_id: str) -> None:
        """Revoke the oldest sessions beyond max_concurrent_sessions."""
        max_sessions = self.config.max_concurrent_sessions
        if max_sessions <= 0:
            return
        active = await self.db.get_active_sessions(user_id)
        if len(active) <= max_sessions:
            return
        active.sort(key=lambda r: _parse_ts(r.get("created_at")))
        for record in active[: len(active) - max_sessions]:
            sid = str(record["id"])
            await self.db.revoke_session(sid)
            await self._drop_session_state(user_id, sid)
            logger.info(
                "Evicted session %s (user %s exceeded %d concurrent sessions)",
                sid,
                user_id,
                max_sessions,
            )

    async def _resolve_session_for_refresh(
        self, refresh_token: str, user_id: str
    ) -> Optional[Session]:
        """Find the session owning a refresh token (cache ledger first)."""
        if self.cache is not None:
            session_id = await self.cache.get(self._refresh_map_key(refresh_token))
            if session_id:
                return await self._get_session(str(session_id))
            return None
        # No cache: fall back to matching the stored token on active sessions.
        for record in await self.db.get_active_sessions(user_id):
            if record.get("refresh_token") == refresh_token:
                return Session.from_dict(record)
        return None

    def _schedule_last_active_update(self, session_id: str) -> None:
        """Fire the last-active update, retaining the task reference (§0)."""
        task = asyncio.create_task(self._update_last_active(session_id))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _update_last_active(self, session_id: str) -> None:
        session = await self._get_session(session_id)
        if session is None or session.is_revoked:
            return
        session.last_active = _utcnow()
        try:
            await self._store_session(session)
        except Exception as exc:  # never let a background update raise
            logger.warning("last_active update failed for %s: %s", session_id, exc)
