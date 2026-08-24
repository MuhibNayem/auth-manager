"""SQL database implementing the full §4 contract (CONTRACTS.md).

Reference :class:`AbstractDatabase` implementation on SQLAlchemy 2.x async
(asyncpg/aiomysql drivers optional; aiosqlite for tests/dev). Semantics
mirror :class:`~tessera.db.memory.InMemoryDatabase`:

- Identifier lookups (email/username) are case-insensitive via ``LOWER()``
  comparisons; uniqueness is enforced by pre-check plus unique expression
  indexes on ``lower(email)`` / ``lower(username)``.
- Records are dicts with the stable contract keys stored in typed columns;
  provider-specific extras go to a JSON ``extra`` column.
- Ids are uuid4 hex strings; timestamps are ISO-8601 UTC strings.
- Audit events carry ``checksum`` = sha256 over canonical JSON of the event
  WITHOUT db-assigned fields (``id``, ``sequence``, ``checksum``), with
  ``previous_checksum`` included in the checksummed payload (hash chain).
- ``revoke_session`` is a single atomic ``UPDATE ... WHERE status='active'``.
- SAML request consume is ``DELETE ... RETURNING`` on dialects that support
  it (PostgreSQL) with a select+delete transaction fallback on SQLite.
- ``update_oidc_provider`` only accepts whitelisted columns; unknown keys
  raise ``ValueError`` (never caller-key interpolation).
- Engine ``echo`` is driven by a config flag (``echo``) defaulting to False.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from tessera.db.abstract_db import AbstractDatabase
from tessera.db.memory import GENESIS_CHECKSUM, OIDC_UPDATABLE_FIELDS
from tessera.errors import DatabaseError, IntegrityError

try:  # pragma: no cover - trivial import guard
    from sqlalchemy import (
        JSON,
        Boolean,
        Float,
        Index,
        Integer,
        String,
        Text,
        delete as sa_delete,
        func,
        select,
        text,
        update as sa_update,
    )
    from sqlalchemy.exc import IntegrityError as SAIntegrityError
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
    from sqlalchemy.pool import StaticPool

    SQLALCHEMY_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without SQLAlchemy
    SQLALCHEMY_AVAILABLE = False

logger = logging.getLogger("tessera.db.sql")

__all__ = ["SQLDatabase"]

#: Fields assigned by the database; excluded from the audit checksum payload.
_AUDIT_DB_ASSIGNED_FIELDS = frozenset({"id", "sequence", "checksum"})

#: Default in-memory SQLite URL used when no connection string is configured.
_DEFAULT_SQLITE_URL = "sqlite+aiosqlite:///:memory:"


def _utcnow() -> datetime:
    """Timezone-aware UTC now (§0.5)."""
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime) -> datetime:
    """Attach UTC to naive datetimes so comparisons never raise."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _iso(dt: datetime) -> str:
    """Normalize a datetime to a fixed-width ISO-8601 UTC string.

    Microsecond precision keeps lexicographic order identical to
    chronological order, which the audit range queries rely on.
    """
    return _ensure_aware(dt).astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    )


def _iso_value(value: Any, default: datetime) -> str:
    """Coerce a caller-provided timestamp (or absent) to ISO-8601 UTC."""
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, str) and value:
        return value
    return _iso(default)


def _new_id() -> str:
    """Random uuid4 hex id (32 chars, secrets-grade randomness)."""
    return uuid.uuid4().hex


def _canonical_json(payload: Dict[str, Any]) -> bytes:
    """Deterministic JSON encoding for audit checksums (memory.py-exact)."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _slugify(value: str) -> str:
    """Derive a URL-safe slug from a name (memory.py-exact)."""
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "org"


def _escape_like(value: str) -> str:
    """Escape LIKE wildcards so search terms match literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


if SQLALCHEMY_AVAILABLE:

    class _Base(DeclarativeBase):
        """Declarative base for all contract tables."""

    class _UserModel(_Base):
        __tablename__ = "users"

        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        username: Mapped[Optional[str]] = mapped_column(String(255))
        email: Mapped[Optional[str]] = mapped_column(String(320))
        phone: Mapped[Optional[str]] = mapped_column(String(64))
        hashed_password: Mapped[Optional[str]] = mapped_column(Text)
        mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
        mfa_secret: Mapped[Optional[str]] = mapped_column(String(255))
        created_at: Mapped[str] = mapped_column(String(64))
        updated_at: Mapped[str] = mapped_column(String(64))
        is_active: Mapped[bool] = mapped_column(Boolean, default=True)
        role: Mapped[str] = mapped_column(String(64), default="user")
        extra: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)

        __table_args__ = (
            Index("uq_users_email_lower", func.lower(email), unique=True),
            Index("uq_users_username_lower", func.lower(username), unique=True),
            Index("uq_users_phone", phone, unique=True),
        )

    class _SessionModel(_Base):
        __tablename__ = "sessions"

        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        user_id: Mapped[str] = mapped_column(String(64), index=True)
        status: Mapped[str] = mapped_column(String(32), default="active")
        created_at: Mapped[str] = mapped_column(String(64))
        revoked_at: Mapped[Optional[str]] = mapped_column(String(64))
        extra: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)

    class _OrganizationModel(_Base):
        __tablename__ = "organizations"

        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        name: Mapped[str] = mapped_column(String(255))
        slug: Mapped[str] = mapped_column(String(255), unique=True)
        created_at: Mapped[str] = mapped_column(String(64))
        updated_at: Mapped[str] = mapped_column(String(64))
        extra: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)

    class _OrgMemberModel(_Base):
        __tablename__ = "org_members"

        org_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        user_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        role: Mapped[str] = mapped_column(String(64), default="member")
        added_at: Mapped[str] = mapped_column(String(64))
        extra: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)

    class _InvitationModel(_Base):
        __tablename__ = "invitations"

        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        org_id: Mapped[str] = mapped_column(String(64), index=True)
        token: Mapped[str] = mapped_column(String(128), unique=True)
        status: Mapped[str] = mapped_column(String(32), default="pending")
        created_at: Mapped[str] = mapped_column(String(64))
        extra: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)

    class _AuditEventModel(_Base):
        __tablename__ = "audit_events"

        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        sequence: Mapped[int] = mapped_column(Integer, unique=True)
        timestamp: Mapped[str] = mapped_column(String(64), index=True)
        event_type: Mapped[Optional[str]] = mapped_column(String(128))
        actor: Mapped[Optional[str]] = mapped_column(String(255))
        target: Mapped[Optional[str]] = mapped_column(String(255))
        checksum: Mapped[str] = mapped_column(String(64))
        previous_checksum: Mapped[str] = mapped_column(String(64))
        #: Checksummed payload minus previous_checksum and db-assigned fields.
        data: Mapped[Dict[str, Any]] = mapped_column(JSON)

    class _WebhookEndpointModel(_Base):
        __tablename__ = "webhook_endpoints"

        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        url: Mapped[str] = mapped_column(Text)
        events: Mapped[List[str]] = mapped_column(JSON, default=list)
        enabled: Mapped[bool] = mapped_column(Boolean, default=True)
        created_at: Mapped[str] = mapped_column(String(64))
        updated_at: Mapped[Optional[str]] = mapped_column(String(64))
        extra: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)

    class _WebhookDeliveryModel(_Base):
        __tablename__ = "webhook_deliveries"

        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        endpoint_id: Mapped[str] = mapped_column(String(64), index=True)
        created_at: Mapped[str] = mapped_column(String(64))
        extra: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)

    class _RoleModel(_Base):
        __tablename__ = "roles"

        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        name: Mapped[str] = mapped_column(String(128), unique=True)
        permissions: Mapped[List[str]] = mapped_column(JSON, default=list)
        created_at: Mapped[str] = mapped_column(String(64))
        updated_at: Mapped[Optional[str]] = mapped_column(String(64))
        extra: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)

    class _RoleAssignmentModel(_Base):
        __tablename__ = "role_assignments"

        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        user_id: Mapped[str] = mapped_column(String(64), index=True)
        role_id: Mapped[str] = mapped_column(String(64), index=True)
        scope_type: Mapped[Optional[str]] = mapped_column(String(64))
        scope_id: Mapped[Optional[str]] = mapped_column(String(64))
        created_at: Mapped[str] = mapped_column(String(64))
        extra: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)

    class _ApiKeyModel(_Base):
        __tablename__ = "api_keys"

        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        name: Mapped[Optional[str]] = mapped_column(String(255))
        key_hash: Mapped[str] = mapped_column(String(128), unique=True)
        scopes: Mapped[List[str]] = mapped_column(JSON, default=list)
        revoked: Mapped[bool] = mapped_column(Boolean, default=False)
        created_at: Mapped[str] = mapped_column(String(64))
        revoked_at: Mapped[Optional[str]] = mapped_column(String(64))
        extra: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)

    class _SettingModel(_Base):
        __tablename__ = "settings"

        key: Mapped[str] = mapped_column(String(255), primary_key=True)
        value: Mapped[Any] = mapped_column(JSON)

    class _SamlRequestModel(_Base):
        __tablename__ = "saml_requests"

        request_id: Mapped[str] = mapped_column(String(255), primary_key=True)
        data: Mapped[Dict[str, Any]] = mapped_column(JSON)
        expires_at: Mapped[float] = mapped_column(Float)

    class _SamlResponseIdModel(_Base):
        __tablename__ = "saml_response_ids"

        response_id: Mapped[str] = mapped_column(String(255), primary_key=True)
        #: NULL expiry = persistent ledger entry (no TTL).
        expires_at: Mapped[Optional[float]] = mapped_column(Float)

    class _SamlUserMappingModel(_Base):
        __tablename__ = "saml_user_mappings"

        name_id: Mapped[str] = mapped_column(String(255), primary_key=True)
        sp_entity_id: Mapped[str] = mapped_column(String(255), primary_key=True)
        user_id: Mapped[str] = mapped_column(String(64))

    class _OidcProviderModel(_Base):
        __tablename__ = "oidc_providers"

        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        name: Mapped[str] = mapped_column(String(255))
        slug: Mapped[str] = mapped_column(String(255), unique=True)
        issuer: Mapped[str] = mapped_column(String(512), unique=True)
        client_id: Mapped[Optional[str]] = mapped_column(String(255))
        client_secret: Mapped[Optional[str]] = mapped_column(Text)
        authorization_endpoint: Mapped[Optional[str]] = mapped_column(Text)
        token_endpoint: Mapped[Optional[str]] = mapped_column(Text)
        userinfo_endpoint: Mapped[Optional[str]] = mapped_column(Text)
        jwks_uri: Mapped[Optional[str]] = mapped_column(Text)
        discovery_url: Mapped[Optional[str]] = mapped_column(Text)
        scopes: Mapped[Optional[List[str]]] = mapped_column(JSON)
        enabled: Mapped[bool] = mapped_column(Boolean, default=True)
        attribute_mapping: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
        created_at: Mapped[str] = mapped_column(String(64))
        updated_at: Mapped[Optional[str]] = mapped_column(String(64))
        extra: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)


#: Typed (non-extra) record keys per table, for row<->dict conversion.
_USER_COLUMNS = (
    "id",
    "username",
    "email",
    "phone",
    "hashed_password",
    "mfa_enabled",
    "mfa_secret",
    "created_at",
    "updated_at",
    "is_active",
    "role",
)
_SESSION_COLUMNS = ("id", "user_id", "status", "created_at", "revoked_at")
_ORG_COLUMNS = ("id", "name", "slug", "created_at", "updated_at")
_MEMBER_COLUMNS = ("org_id", "user_id", "role", "added_at")
_INVITATION_COLUMNS = ("id", "org_id", "token", "status", "created_at")
_ENDPOINT_COLUMNS = ("id", "url", "events", "enabled", "created_at", "updated_at")
_DELIVERY_COLUMNS = ("id", "endpoint_id", "created_at")
_ROLE_COLUMNS = ("id", "name", "permissions", "created_at", "updated_at")
_ASSIGNMENT_COLUMNS = (
    "id",
    "user_id",
    "role_id",
    "scope_type",
    "scope_id",
    "created_at",
)
_API_KEY_COLUMNS = (
    "id",
    "name",
    "key_hash",
    "scopes",
    "revoked",
    "created_at",
    "revoked_at",
)
_OIDC_COLUMNS = (
    "id",
    "name",
    "slug",
    "issuer",
    "client_id",
    "client_secret",
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "discovery_url",
    "scopes",
    "enabled",
    "attribute_mapping",
    "created_at",
    "updated_at",
)

#: list_users() filters may only target these typed columns.
_USER_FILTERABLE = frozenset(_USER_COLUMNS)


def _split_known(
    data: Dict[str, Any], known: Tuple[str, ...]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Split a record into typed-column values and JSON extras."""
    known_part = {k: v for k, v in data.items() if k in known}
    extra_part = {k: v for k, v in data.items() if k not in known}
    return known_part, extra_part


def _row_to_doc(row: Any, columns: Tuple[str, ...]) -> Dict[str, Any]:
    """Convert an ORM row to a contract dict (typed keys + extras).

    Typed columns win over extras; ``None`` typed values are omitted so
    absent fields look exactly like the in-memory reference.
    """
    doc = {k: getattr(row, k) for k in columns if getattr(row, k) is not None}
    extra = getattr(row, "extra", None)
    if extra:
        doc = {**extra, **doc}
    return doc


class SQLDatabase(AbstractDatabase):
    """Full-contract async SQL database (SQLAlchemy 2.x).

    Args:
        config: A :class:`~tessera.config.DatabaseConfig` (uses
            ``connection_string`` and optional ``echo`` flag) or a plain
            connection URL string. When no URL is configured, an in-memory
            SQLite database is used (development convenience).
    """

    def __init__(self, config: Any = None) -> None:
        if not SQLALCHEMY_AVAILABLE:
            raise ImportError(
                "SQLDatabase requires SQLAlchemy >= 2.0 and an async driver "
                "(e.g. 'pip install sqlalchemy aiosqlite' or 'asyncpg')"
            )
        if isinstance(config, str):
            connection_string: str = config
            echo = False
        else:
            connection_string = getattr(config, "connection_string", "") or ""
            echo = bool(
                getattr(config, "echo", False) or getattr(config, "echo_sql", False)
            )
        if not connection_string:
            logger.warning(
                "SQLDatabase: no connection_string configured; falling back "
                "to in-memory SQLite (tests/dev only)"
            )
            connection_string = _DEFAULT_SQLITE_URL
        self._url = connection_string
        self._echo = echo
        self._engine = None
        self._session_factory: Optional[async_sessionmaker] = None
        # Serializes hash-chain appends and single-row atomic consumes.
        self._audit_lock = asyncio.Lock()
        self._kv_lock = asyncio.Lock()

    # -- lifecycle -----------------------------------------------------------

    async def connect(self) -> None:
        """Create the engine/pool and all contract tables."""
        if self._engine is not None:
            return
        kwargs: Dict[str, Any] = {"echo": self._echo}
        if self._url.startswith("sqlite") and ":memory:" in self._url:
            # One shared connection so the in-memory DB survives checkout.
            kwargs["poolclass"] = StaticPool
        self._engine = create_async_engine(self._url, **kwargs)
        self._session_factory = async_sessionmaker(
            bind=self._engine, class_=AsyncSession, expire_on_commit=False
        )
        async with self._engine.begin() as conn:
            await conn.run_sync(_Base.metadata.create_all)
        logger.info("SQLDatabase connected (%s)", self._url)

    async def close(self) -> None:
        """Dispose of the engine and its connection pool."""
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None

    async def health_check(self) -> bool:
        """Run ``SELECT 1``; ``True`` when the database answers."""
        if self._engine is None:
            return False
        try:
            async with self._engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception:  # noqa: BLE001 - health checks report, never raise
            logger.exception("SQL health check failed")
            return False

    def _require_engine(self) -> None:
        if self._engine is None or self._session_factory is None:
            raise DatabaseError(
                "SQLDatabase is not connected; call connect() first",
                code="not_connected",
            )

    # -- users ----------------------------------------------------------------

    async def _check_unique_identifiers(
        self,
        session: AsyncSession,
        *,
        email: Optional[str] = None,
        username: Optional[str] = None,
        phone: Optional[str] = None,
        exclude_user_id: Optional[str] = None,
    ) -> None:
        """Pre-check identifier uniqueness (case-insensitive email/username)."""
        checks = (
            (_UserModel.email, email, str(email).lower() if email else None, "email"),
            (
                _UserModel.username,
                username,
                str(username).lower() if username else None,
                "username",
            ),
            (_UserModel.phone, phone, str(phone) if phone else None, "phone"),
        )
        for column, raw, normalized, label in checks:
            if not raw:
                continue
            if label == "phone":
                condition = column == normalized
            else:
                condition = func.lower(column) == normalized
            if exclude_user_id is not None:
                condition = condition & (_UserModel.id != exclude_user_id)
            existing = (
                await session.execute(select(_UserModel.id).where(condition))
            ).first()
            if existing is not None:
                raise IntegrityError(
                    f"A user with {label} {raw!r} already exists"
                )

    async def create_user(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """Create a user with unique email/username/phone enforcement."""
        self._require_engine()
        if not isinstance(user, dict):
            raise ValueError("user must be a dict")
        record = dict(user)
        record.setdefault("id", _new_id())
        now = _utcnow()
        record["created_at"] = _iso_value(record.get("created_at"), now)
        record["updated_at"] = _iso_value(record.get("updated_at"), now)
        record.setdefault("is_active", True)
        record.setdefault("mfa_enabled", False)
        record.setdefault("role", "user")

        known, extra = _split_known(record, _USER_COLUMNS)
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                await self._check_unique_identifiers(
                    session,
                    email=record.get("email"),
                    username=record.get("username"),
                    phone=record.get("phone"),
                )
                try:
                    session.add(_UserModel(**known, extra=extra or None))
                    await session.flush()
                except SAIntegrityError as exc:
                    raise IntegrityError(
                        "A user with one of these identifiers already exists"
                    ) from exc
        return dict(record)

    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            row = (
                await session.execute(
                    select(_UserModel).where(_UserModel.id == user_id)
                )
            ).scalar_one_or_none()
        return _row_to_doc(row, _USER_COLUMNS) if row else None

    async def get_user_by_identifier(
        self,
        *,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Look up one user; email/username case-insensitive, phone exact."""
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            if email:
                row = (
                    await session.execute(
                        select(_UserModel).where(
                            func.lower(_UserModel.email) == str(email).lower()
                        )
                    )
                ).scalar_one_or_none()
                if row:
                    return _row_to_doc(row, _USER_COLUMNS)
            if username:
                row = (
                    await session.execute(
                        select(_UserModel).where(
                            func.lower(_UserModel.username) == str(username).lower()
                        )
                    )
                ).scalar_one_or_none()
                if row:
                    return _row_to_doc(row, _USER_COLUMNS)
            if phone:
                row = (
                    await session.execute(
                        select(_UserModel).where(_UserModel.phone == str(phone))
                    )
                ).scalar_one_or_none()
                if row:
                    return _row_to_doc(row, _USER_COLUMNS)
        return None

    async def update_user(
        self, user_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        self._require_engine()
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        if "id" in updates or "created_at" in updates:
            raise ValueError("id and created_at are immutable")
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                row = (
                    await session.execute(
                        select(_UserModel).where(_UserModel.id == user_id)
                    )
                ).scalar_one_or_none()
                if row is None:
                    return None
                await self._check_unique_identifiers(
                    session,
                    email=updates.get("email", row.email),
                    username=updates.get("username", row.username),
                    phone=updates.get("phone", row.phone),
                    exclude_user_id=user_id,
                )
                try:
                    known_updates = {
                        k: v for k, v in updates.items() if k in _USER_COLUMNS
                    }
                    if "updated_at" not in known_updates:
                        known_updates["updated_at"] = _iso(_utcnow())
                    elif isinstance(known_updates["updated_at"], datetime):
                        known_updates["updated_at"] = _iso(known_updates["updated_at"])
                    for key, value in known_updates.items():
                        setattr(row, key, value)
                    extra_updates = {
                        k: v for k, v in updates.items() if k not in _USER_COLUMNS
                    }
                    if extra_updates:
                        merged = {**(row.extra or {}), **extra_updates}
                        row.extra = merged
                    await session.flush()
                except SAIntegrityError as exc:
                    raise IntegrityError(
                        "A user with one of these identifiers already exists"
                    ) from exc
                return _row_to_doc(row, _USER_COLUMNS)

    async def delete_user(self, user_id: str) -> bool:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                result = await session.execute(
                    sa_delete(_UserModel).where(_UserModel.id == user_id)
                )
        return (result.rowcount or 0) > 0

    async def list_users(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List users with pagination; returns ``(rows, total_matching)``."""
        self._require_engine()
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        conditions = []
        if search:
            haystack = func.lower(
                func.coalesce(_UserModel.username, "")
                + " "
                + func.coalesce(_UserModel.email, "")
            )
            conditions.append(
                haystack.like(f"%{_escape_like(search.lower())}%", escape="\\")
            )
        if filters:
            for key, expected in filters.items():
                if key not in _USER_FILTERABLE:
                    raise ValueError(
                        f"list_users filter {key!r} is not a filterable column"
                    )
                conditions.append(getattr(_UserModel, key) == expected)

        async with self._session_factory() as session:  # type: ignore[misc]
            base = select(_UserModel).where(*conditions)
            total = (
                await session.execute(
                    select(func.count()).select_from(base.subquery())
                )
            ).scalar_one()
            rows_result = await session.execute(
                base.order_by(_UserModel.created_at, _UserModel.id)
                .limit(limit)
                .offset(offset)
            )
            rows = [_row_to_doc(r, _USER_COLUMNS) for r in rows_result.scalars()]
        return rows, int(total)

    async def count_users(
        self,
        *,
        active_only: bool = False,
        mfa_enabled: Optional[bool] = None,
        created_since: Optional[datetime] = None,
    ) -> int:
        self._require_engine()
        conditions = []
        if active_only:
            conditions.append(_UserModel.is_active.is_(True))
        if mfa_enabled is not None:
            conditions.append(_UserModel.mfa_enabled.is_(bool(mfa_enabled)))
        if created_since is not None:
            conditions.append(
                _UserModel.created_at >= _iso(_ensure_aware(created_since))
            )
        async with self._session_factory() as session:  # type: ignore[misc]
            total = (
                await session.execute(
                    select(func.count(_UserModel.id)).where(*conditions)
                )
            ).scalar_one()
        return int(total)

    # -- sessions ---------------------------------------------------------------

    async def save_session(self, session: Dict[str, Any]) -> None:
        """Insert or replace a session document."""
        self._require_engine()
        if not isinstance(session, dict):
            raise ValueError("session must be a dict")
        if not session.get("user_id"):
            raise ValueError("session.user_id is required")
        record = dict(session)
        record.setdefault("id", _new_id())
        record.setdefault("status", "active")
        record["created_at"] = _iso_value(record.get("created_at"), _utcnow())
        known, extra = _split_known(record, _SESSION_COLUMNS)
        async with self._session_factory() as session_:  # type: ignore[misc]
            async with session_.begin():
                await session_.execute(
                    sa_delete(_SessionModel).where(
                        _SessionModel.id == record["id"]
                    )
                )
                session_.add(_SessionModel(**known, extra=extra or None))

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            row = (
                await session.execute(
                    select(_SessionModel).where(_SessionModel.id == session_id)
                )
            ).scalar_one_or_none()
        return _row_to_doc(row, _SESSION_COLUMNS) if row else None

    async def get_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            result = await session.execute(
                select(_SessionModel).where(
                    _SessionModel.user_id == user_id,
                    _SessionModel.status == "active",
                )
            )
            return [_row_to_doc(r, _SESSION_COLUMNS) for r in result.scalars()]

    async def revoke_session(self, session_id: str) -> bool:
        """Atomic status flip: only the first revoke of an active session wins."""
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                result = await session.execute(
                    sa_update(_SessionModel)
                    .where(
                        _SessionModel.id == session_id,
                        _SessionModel.status == "active",
                    )
                    .values(
                        status="revoked",
                        revoked_at=_iso(_utcnow()),
                    )
                )
        return (result.rowcount or 0) == 1

    async def revoke_all_user_sessions(self, user_id: str) -> int:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                result = await session.execute(
                    sa_update(_SessionModel)
                    .where(
                        _SessionModel.user_id == user_id,
                        _SessionModel.status == "active",
                    )
                    .values(status="revoked", revoked_at=_iso(_utcnow()))
                )
        return int(result.rowcount or 0)


    # -- organizations -------------------------------------------------------

    async def create_organization(self, org: Dict[str, Any]) -> Dict[str, Any]:
        """Create an organization with a unique slug."""
        self._require_engine()
        if not isinstance(org, dict):
            raise ValueError("org must be a dict")
        record = dict(org)
        if not record.get("name"):
            raise ValueError("org.name is required")
        record.setdefault("id", _new_id())
        record.setdefault("slug", _slugify(str(record["name"])))
        record["slug"] = str(record["slug"]).lower()
        now = _utcnow()
        record["created_at"] = _iso_value(record.get("created_at"), now)
        record["updated_at"] = _iso_value(record.get("updated_at"), now)

        known, extra = _split_known(record, _ORG_COLUMNS)
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                existing = (
                    await session.execute(
                        select(_OrganizationModel.id).where(
                            _OrganizationModel.slug == record["slug"]
                        )
                    )
                ).first()
                if existing is not None:
                    raise IntegrityError(
                        f"An organization with slug {record['slug']!r} already exists"
                    )
                try:
                    session.add(_OrganizationModel(**known, extra=extra or None))
                    await session.flush()
                except SAIntegrityError as exc:
                    raise IntegrityError(
                        f"An organization with slug {record['slug']!r} already exists"
                    ) from exc
        return dict(record)

    async def get_organization(self, org_id: str) -> Optional[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            row = (
                await session.execute(
                    select(_OrganizationModel).where(
                        _OrganizationModel.id == org_id
                    )
                )
            ).scalar_one_or_none()
        return _row_to_doc(row, _ORG_COLUMNS) if row else None

    async def get_organization_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            row = (
                await session.execute(
                    select(_OrganizationModel).where(
                        _OrganizationModel.slug == str(slug).lower()
                    )
                )
            ).scalar_one_or_none()
        return _row_to_doc(row, _ORG_COLUMNS) if row else None

    async def update_organization(
        self, org_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        self._require_engine()
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        if "id" in updates:
            raise ValueError("id is immutable")
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                row = (
                    await session.execute(
                        select(_OrganizationModel).where(
                            _OrganizationModel.id == org_id
                        )
                    )
                ).scalar_one_or_none()
                if row is None:
                    return None
                new_slug = updates.get("slug")
                if new_slug is not None:
                    candidate = str(new_slug).lower()
                    owner = (
                        await session.execute(
                            select(_OrganizationModel.id).where(
                                _OrganizationModel.slug == candidate
                            )
                        )
                    ).scalar_one_or_none()
                    if owner is not None and owner != org_id:
                        raise IntegrityError(
                            f"An organization with slug {candidate!r} already exists"
                        )
                    updates = {**updates, "slug": candidate}
                try:
                    known_updates = {
                        k: v for k, v in updates.items() if k in _ORG_COLUMNS
                    }
                    known_updates["updated_at"] = _iso(_utcnow())
                    for key, value in known_updates.items():
                        setattr(row, key, value)
                    extra_updates = {
                        k: v for k, v in updates.items() if k not in _ORG_COLUMNS
                    }
                    if extra_updates:
                        row.extra = {**(row.extra or {}), **extra_updates}
                    await session.flush()
                except SAIntegrityError as exc:
                    raise IntegrityError(
                        "Organization slug conflicts with another organization"
                    ) from exc
                return _row_to_doc(row, _ORG_COLUMNS)

    async def delete_organization(self, org_id: str) -> bool:
        """Delete an organization and its member/invitation links."""
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                await session.execute(
                    sa_delete(_OrgMemberModel).where(
                        _OrgMemberModel.org_id == org_id
                    )
                )
                await session.execute(
                    sa_delete(_InvitationModel).where(
                        _InvitationModel.org_id == org_id
                    )
                )
                result = await session.execute(
                    sa_delete(_OrganizationModel).where(
                        _OrganizationModel.id == org_id
                    )
                )
        return (result.rowcount or 0) > 0

    async def list_organizations(
        self, *, limit: int = 50, offset: int = 0
    ) -> Tuple[List[Dict[str, Any]], int]:
        self._require_engine()
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        async with self._session_factory() as session:  # type: ignore[misc]
            total = (
                await session.execute(
                    select(func.count(_OrganizationModel.id))
                )
            ).scalar_one()
            result = await session.execute(
                select(_OrganizationModel)
                .order_by(_OrganizationModel.created_at, _OrganizationModel.id)
                .limit(limit)
                .offset(offset)
            )
            rows = [_row_to_doc(r, _ORG_COLUMNS) for r in result.scalars()]
        return rows, int(total)

    async def add_org_member(self, org_id: str, member: Dict[str, Any]) -> Dict[str, Any]:
        """Add a member to an organization."""
        self._require_engine()
        if not isinstance(member, dict) or not member.get("user_id"):
            raise ValueError("member must be a dict with a user_id")
        record = dict(member)
        record["user_id"] = str(record["user_id"])
        record.setdefault("role", "member")
        record["added_at"] = _iso_value(record.get("added_at"), _utcnow())
        known, extra = _split_known(record, _MEMBER_COLUMNS)
        known["org_id"] = org_id
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                org_exists = (
                    await session.execute(
                        select(_OrganizationModel.id).where(
                            _OrganizationModel.id == org_id
                        )
                    )
                ).first()
                if org_exists is None:
                    raise IntegrityError(
                        f"Organization {org_id!r} does not exist"
                    )
                try:
                    session.add(_OrgMemberModel(**known, extra=extra or None))
                    await session.flush()
                except SAIntegrityError as exc:
                    raise IntegrityError(
                        f"User {record['user_id']!r} is already a member of "
                        f"{org_id!r}"
                    ) from exc
        return dict(record)

    async def get_org_members(self, org_id: str) -> List[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            result = await session.execute(
                select(_OrgMemberModel)
                .where(_OrgMemberModel.org_id == org_id)
                .order_by(_OrgMemberModel.added_at, _OrgMemberModel.user_id)
            )
            return [_row_to_doc(r, _MEMBER_COLUMNS) for r in result.scalars()]

    async def update_org_member(
        self, org_id: str, user_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        self._require_engine()
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        if "user_id" in updates:
            raise ValueError("user_id is immutable")
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                row = (
                    await session.execute(
                        select(_OrgMemberModel).where(
                            _OrgMemberModel.org_id == org_id,
                            _OrgMemberModel.user_id == str(user_id),
                        )
                    )
                ).scalar_one_or_none()
                if row is None:
                    return None
                for key, value in updates.items():
                    if key in _MEMBER_COLUMNS:
                        setattr(row, key, value)
                extra_updates = {
                    k: v for k, v in updates.items() if k not in _MEMBER_COLUMNS
                }
                if extra_updates:
                    row.extra = {**(row.extra or {}), **extra_updates}
                await session.flush()
                return _row_to_doc(row, _MEMBER_COLUMNS)

    async def remove_org_member(self, org_id: str, user_id: str) -> bool:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                result = await session.execute(
                    sa_delete(_OrgMemberModel).where(
                        _OrgMemberModel.org_id == org_id,
                        _OrgMemberModel.user_id == str(user_id),
                    )
                )
        return (result.rowcount or 0) > 0

    async def create_invitation(self, invitation: Dict[str, Any]) -> Dict[str, Any]:
        """Create an org invitation (token generated when absent)."""
        self._require_engine()
        if not isinstance(invitation, dict) or not invitation.get("org_id"):
            raise ValueError("invitation must be a dict with an org_id")
        record = dict(invitation)
        record.setdefault("id", _new_id())
        record.setdefault("token", _invitation_token())
        record.setdefault("status", "pending")
        record["created_at"] = _iso_value(record.get("created_at"), _utcnow())
        known, extra = _split_known(record, _INVITATION_COLUMNS)
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                org_exists = (
                    await session.execute(
                        select(_OrganizationModel.id).where(
                            _OrganizationModel.id == record["org_id"]
                        )
                    )
                ).first()
                if org_exists is None:
                    raise IntegrityError(
                        f"Organization {record['org_id']!r} does not exist"
                    )
                session.add(_InvitationModel(**known, extra=extra or None))
                await session.flush()
        return dict(record)

    async def get_invitation_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            row = (
                await session.execute(
                    select(_InvitationModel).where(_InvitationModel.token == token)
                )
            ).scalar_one_or_none()
        return _row_to_doc(row, _INVITATION_COLUMNS) if row else None

    async def get_pending_invitations(self, org_id: str) -> List[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            result = await session.execute(
                select(_InvitationModel)
                .where(
                    _InvitationModel.org_id == org_id,
                    _InvitationModel.status == "pending",
                )
                .order_by(_InvitationModel.created_at, _InvitationModel.id)
            )
            return [_row_to_doc(r, _INVITATION_COLUMNS) for r in result.scalars()]

    async def delete_invitation(self, invitation_id: str) -> bool:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                result = await session.execute(
                    sa_delete(_InvitationModel).where(
                        _InvitationModel.id == invitation_id
                    )
                )
        return (result.rowcount or 0) > 0

    # -- audit log --------------------------------------------------------------

    @staticmethod
    def _audit_checksum(payload: Dict[str, Any], previous_checksum: str) -> str:
        """sha256 over canonical JSON incl. ``previous_checksum`` (hash chain)."""
        return hashlib.sha256(
            _canonical_json({**payload, "previous_checksum": previous_checksum})
        ).hexdigest()

    def _prepare_audit_record(
        self, event: Dict[str, Any], previous_checksum: str, sequence: int
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Assign db fields and compute the checksum for one event.

        Returns ``(stored_doc, payload_for_data_column)`` where the payload is
        the JSON-normalized checksummed content minus ``previous_checksum``
        and db-assigned fields.
        """
        if not isinstance(event, dict):
            raise ValueError("event must be a dict")
        record = dict(event)
        record_id = record.setdefault("id", _new_id())
        record["timestamp"] = _iso_value(record.get("timestamp"), _utcnow())
        payload = {
            key: value
            for key, value in record.items()
            if key not in _AUDIT_DB_ASSIGNED_FIELDS and key != "previous_checksum"
        }
        # JSON-normalize so read-back recomputation is byte-identical.
        payload = json.loads(json.dumps(payload, default=str))
        checksum = self._audit_checksum(payload, previous_checksum)
        doc = {
            **payload,
            "id": record_id,
            "sequence": sequence,
            "checksum": checksum,
            "previous_checksum": previous_checksum,
        }
        return doc, payload

    async def _last_audit_state(
        self, session: AsyncSession
    ) -> Tuple[str, int]:
        row = (
            await session.execute(
                select(_AuditEventModel.checksum, _AuditEventModel.sequence)
                .order_by(_AuditEventModel.sequence.desc())
                .limit(1)
            )
        ).first()
        if row is None:
            return GENESIS_CHECKSUM, 0
        return row.checksum, int(row.sequence)

    def _insert_audit_row(
        self, session: AsyncSession, doc: Dict[str, Any], payload: Dict[str, Any]
    ) -> None:
        session.add(
            _AuditEventModel(
                id=doc["id"],
                sequence=doc["sequence"],
                timestamp=doc["timestamp"],
                event_type=payload.get("event_type"),
                actor=payload.get("actor"),
                target=payload.get("target"),
                checksum=doc["checksum"],
                previous_checksum=doc["previous_checksum"],
                data=payload,
            )
        )

    async def save_audit_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Append one event to the hash chain."""
        self._require_engine()
        async with self._audit_lock:
            async with self._session_factory() as session:  # type: ignore[misc]
                async with session.begin():
                    previous, sequence = await self._last_audit_state(session)
                    doc, payload = self._prepare_audit_record(
                        event, previous, sequence + 1
                    )
                    self._insert_audit_row(session, doc, payload)
        return doc

    async def save_audit_events(self, events: List[Dict[str, Any]]) -> int:
        """Append events in order; all-or-nothing (single transaction)."""
        self._require_engine()
        if not isinstance(events, list):
            raise ValueError("events must be a list")
        async with self._audit_lock:
            async with self._session_factory() as session:  # type: ignore[misc]
                async with session.begin():
                    previous, sequence = await self._last_audit_state(session)
                    for event in events:
                        sequence += 1
                        doc, payload = self._prepare_audit_record(
                            event, previous, sequence
                        )
                        self._insert_audit_row(session, doc, payload)
                        previous = doc["checksum"]
        return len(events)

    def _audit_row_to_doc(self, row: Any) -> Dict[str, Any]:
        data = dict(row.data or {})
        data.update(
            {
                "id": row.id,
                "sequence": row.sequence,
                "checksum": row.checksum,
                "previous_checksum": row.previous_checksum,
            }
        )
        return data

    async def search_audit_events(
        self,
        *,
        event_types: Optional[List[str]] = None,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Search events newest-first with pagination and totals."""
        self._require_engine()
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        conditions = []
        if event_types:
            conditions.append(_AuditEventModel.event_type.in_(list(event_types)))
        if actor is not None:
            conditions.append(_AuditEventModel.actor == actor)
        if target is not None:
            conditions.append(_AuditEventModel.target == target)
        if start is not None:
            conditions.append(
                _AuditEventModel.timestamp >= _iso(_ensure_aware(start))
            )
        if end is not None:
            conditions.append(
                _AuditEventModel.timestamp <= _iso(_ensure_aware(end))
            )
        async with self._session_factory() as session:  # type: ignore[misc]
            base = select(_AuditEventModel).where(*conditions)
            total = (
                await session.execute(
                    select(func.count()).select_from(base.subquery())
                )
            ).scalar_one()
            result = await session.execute(
                base.order_by(
                    _AuditEventModel.timestamp.desc(),
                    _AuditEventModel.sequence.desc(),
                )
                .limit(limit)
                .offset(offset)
            )
            rows = [self._audit_row_to_doc(r) for r in result.scalars()]
        return rows, int(total)

    async def get_audit_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            row = (
                await session.execute(
                    select(_AuditEventModel).where(_AuditEventModel.id == event_id)
                )
            ).scalar_one_or_none()
        return self._audit_row_to_doc(row) if row else None

    async def delete_audit_events_before(self, ts: datetime) -> int:
        """Prune events older than ``ts``; returns the count deleted."""
        self._require_engine()
        async with self._audit_lock:
            async with self._session_factory() as session:  # type: ignore[misc]
                async with session.begin():
                    result = await session.execute(
                        sa_delete(_AuditEventModel).where(
                            _AuditEventModel.timestamp < _iso(_ensure_aware(ts))
                        )
                    )
        return int(result.rowcount or 0)

    async def get_audit_statistics(
        self, *, since: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Aggregate audit statistics (totals, per-type, per-actor)."""
        self._require_engine()
        conditions = []
        if since is not None:
            conditions.append(
                _AuditEventModel.timestamp >= _iso(_ensure_aware(since))
            )
        async with self._session_factory() as session:  # type: ignore[misc]
            result = await session.execute(
                select(
                    _AuditEventModel.timestamp,
                    _AuditEventModel.event_type,
                    _AuditEventModel.actor,
                ).where(*conditions)
            )
            rows = result.all()
        total = 0
        by_type: Dict[str, int] = {}
        by_actor: Dict[str, int] = {}
        first_at: Optional[datetime] = None
        last_at: Optional[datetime] = None
        for timestamp, event_type, actor in rows:
            total += 1
            record = {
                key: value
                for key, value in (
                    ("event_type", event_type),
                    ("actor", actor),
                )
                if value is not None
            }
            type_key = str(record.get("event_type", "unknown"))
            actor_key = str(record.get("actor", "unknown"))
            by_type[type_key] = by_type.get(type_key, 0) + 1
            by_actor[actor_key] = by_actor.get(actor_key, 0) + 1
            when = datetime.fromisoformat(timestamp)
            if first_at is None or when < first_at:
                first_at = when
            if last_at is None or when > last_at:
                last_at = when
        return {
            "total_events": total,
            "events_by_type": by_type,
            "events_by_actor": by_actor,
            "first_event_at": first_at,
            "last_event_at": last_at,
        }

    async def get_audit_time_series(
        self, *, since: datetime, bucket_seconds: int
    ) -> List[Dict[str, Any]]:
        """Bucketed event counts from ``since`` until now (UTC)."""
        self._require_engine()
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be positive")
        start = _ensure_aware(since)
        now = _utcnow()
        if start > now:
            return []
        async with self._session_factory() as session:  # type: ignore[misc]
            result = await session.execute(
                select(_AuditEventModel.timestamp).where(
                    _AuditEventModel.timestamp >= _iso(start),
                    _AuditEventModel.timestamp <= _iso(now),
                )
            )
            timestamps = [datetime.fromisoformat(r[0]) for r in result.all()]
        bucket_count = int((now - start).total_seconds() // bucket_seconds) + 1
        buckets = [
            {
                "bucket_start": datetime.fromtimestamp(
                    start.timestamp() + i * bucket_seconds, tz=timezone.utc
                ),
                "count": 0,
            }
            for i in range(bucket_count)
        ]
        for when in timestamps:
            index = int((when - start).total_seconds() // bucket_seconds)
            buckets[min(index, bucket_count - 1)]["count"] += 1
        return buckets


    # -- webhooks ----------------------------------------------------------------

    async def save_webhook_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Create a webhook endpoint record."""
        self._require_engine()
        if not isinstance(endpoint, dict) or not endpoint.get("url"):
            raise ValueError("endpoint must be a dict with a url")
        record = dict(endpoint)
        record.setdefault("id", _new_id())
        record.setdefault("events", [])
        record.setdefault("enabled", True)
        record["created_at"] = _iso_value(record.get("created_at"), _utcnow())
        known, extra = _split_known(record, _ENDPOINT_COLUMNS)
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                session.add(_WebhookEndpointModel(**known, extra=extra or None))
                await session.flush()
        return dict(record)

    async def get_webhook_endpoint(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            row = (
                await session.execute(
                    select(_WebhookEndpointModel).where(
                        _WebhookEndpointModel.id == endpoint_id
                    )
                )
            ).scalar_one_or_none()
        return _row_to_doc(row, _ENDPOINT_COLUMNS) if row else None

    async def list_webhook_endpoints(self) -> List[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            result = await session.execute(
                select(_WebhookEndpointModel).order_by(
                    _WebhookEndpointModel.created_at, _WebhookEndpointModel.id
                )
            )
            return [_row_to_doc(r, _ENDPOINT_COLUMNS) for r in result.scalars()]

    async def update_webhook_endpoint(
        self, endpoint_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        self._require_engine()
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        if "id" in updates:
            raise ValueError("id is immutable")
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                row = (
                    await session.execute(
                        select(_WebhookEndpointModel).where(
                            _WebhookEndpointModel.id == endpoint_id
                        )
                    )
                ).scalar_one_or_none()
                if row is None:
                    return None
                for key, value in updates.items():
                    if key in _ENDPOINT_COLUMNS:
                        setattr(row, key, value)
                extra_updates = {
                    k: v for k, v in updates.items() if k not in _ENDPOINT_COLUMNS
                }
                if extra_updates:
                    row.extra = {**(row.extra or {}), **extra_updates}
                row.updated_at = _iso(_utcnow())
                await session.flush()
                return _row_to_doc(row, _ENDPOINT_COLUMNS)

    async def delete_webhook_endpoint(self, endpoint_id: str) -> bool:
        """Delete an endpoint and its delivery history."""
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                await session.execute(
                    sa_delete(_WebhookDeliveryModel).where(
                        _WebhookDeliveryModel.endpoint_id == endpoint_id
                    )
                )
                result = await session.execute(
                    sa_delete(_WebhookEndpointModel).where(
                        _WebhookEndpointModel.id == endpoint_id
                    )
                )
        return (result.rowcount or 0) > 0

    async def save_webhook_delivery(self, delivery: Dict[str, Any]) -> Dict[str, Any]:
        """Record a delivery attempt for an endpoint."""
        self._require_engine()
        if not isinstance(delivery, dict) or not delivery.get("endpoint_id"):
            raise ValueError("delivery must be a dict with an endpoint_id")
        record = dict(delivery)
        record.setdefault("id", _new_id())
        record["created_at"] = _iso_value(record.get("created_at"), _utcnow())
        known, extra = _split_known(record, _DELIVERY_COLUMNS)
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                endpoint_exists = (
                    await session.execute(
                        select(_WebhookEndpointModel.id).where(
                            _WebhookEndpointModel.id == record["endpoint_id"]
                        )
                    )
                ).first()
                if endpoint_exists is None:
                    raise IntegrityError(
                        f"Webhook endpoint {record['endpoint_id']!r} does not exist"
                    )
                session.add(_WebhookDeliveryModel(**known, extra=extra or None))
                await session.flush()
        return dict(record)

    async def get_webhook_deliveries(
        self, endpoint_id: str, *, limit: int = 50
    ) -> List[Dict[str, Any]]:
        self._require_engine()
        if limit < 0:
            raise ValueError("limit must be non-negative")
        async with self._session_factory() as session:  # type: ignore[misc]
            result = await session.execute(
                select(_WebhookDeliveryModel)
                .where(_WebhookDeliveryModel.endpoint_id == endpoint_id)
                .order_by(
                    _WebhookDeliveryModel.created_at.desc(),
                    _WebhookDeliveryModel.id.desc(),
                )
                .limit(limit)
            )
            return [_row_to_doc(r, _DELIVERY_COLUMNS) for r in result.scalars()]

    # -- RBAC ---------------------------------------------------------------------

    async def save_role(self, role: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update a role (unique name)."""
        self._require_engine()
        if not isinstance(role, dict) or not role.get("name"):
            raise ValueError("role must be a dict with a name")
        record = dict(role)
        role_id = record.get("id")
        record.setdefault("permissions", [])
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                duplicate_condition = _RoleModel.name == record["name"]
                if role_id:
                    duplicate_condition = duplicate_condition & (
                        _RoleModel.id != role_id
                    )
                duplicate = (
                    await session.execute(
                        select(_RoleModel.id).where(duplicate_condition)
                    )
                ).first()
                if duplicate is not None:
                    raise IntegrityError(
                        f"A role named {record['name']!r} already exists"
                    )
                existing = None
                if role_id:
                    existing = (
                        await session.execute(
                            select(_RoleModel).where(_RoleModel.id == role_id)
                        )
                    ).scalar_one_or_none()
                if existing is None:
                    record.setdefault("id", _new_id())
                    record["created_at"] = _iso_value(
                        record.get("created_at"), _utcnow()
                    )
                    record["updated_at"] = _iso(_utcnow())
                    known, extra = _split_known(record, _ROLE_COLUMNS)
                    try:
                        session.add(_RoleModel(**known, extra=extra or None))
                        await session.flush()
                    except SAIntegrityError as exc:
                        raise IntegrityError(
                            f"A role named {record['name']!r} already exists"
                        ) from exc
                else:
                    record["created_at"] = existing.created_at
                    record["updated_at"] = _iso(_utcnow())
                    known, extra = _split_known(record, _ROLE_COLUMNS)
                    for key, value in known.items():
                        setattr(existing, key, value)
                    existing.extra = extra or None
                    await session.flush()
        return dict(record)

    async def get_role(self, role_id: str) -> Optional[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            row = (
                await session.execute(
                    select(_RoleModel).where(_RoleModel.id == role_id)
                )
            ).scalar_one_or_none()
        return _row_to_doc(row, _ROLE_COLUMNS) if row else None

    async def list_roles(self) -> List[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            result = await session.execute(
                select(_RoleModel).order_by(_RoleModel.created_at, _RoleModel.id)
            )
            return [_row_to_doc(r, _ROLE_COLUMNS) for r in result.scalars()]

    async def delete_role(self, role_id: str) -> bool:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                assignments = (
                    await session.execute(
                        select(func.count(_RoleAssignmentModel.id)).where(
                            _RoleAssignmentModel.role_id == role_id
                        )
                    )
                ).scalar_one()
                if assignments:
                    raise IntegrityError(
                        f"Role {role_id!r} still has assignments; remove them first"
                    )
                result = await session.execute(
                    sa_delete(_RoleModel).where(_RoleModel.id == role_id)
                )
        return (result.rowcount or 0) > 0

    async def save_role_assignment(self, assignment: Dict[str, Any]) -> Dict[str, Any]:
        """Create a role assignment (role must exist)."""
        self._require_engine()
        if not isinstance(assignment, dict):
            raise ValueError("assignment must be a dict")
        if not assignment.get("user_id") or not assignment.get("role_id"):
            raise ValueError("assignment requires user_id and role_id")
        record = dict(assignment)
        record.setdefault("id", _new_id())
        record["created_at"] = _iso_value(record.get("created_at"), _utcnow())
        known, extra = _split_known(record, _ASSIGNMENT_COLUMNS)
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                role_exists = (
                    await session.execute(
                        select(_RoleModel.id).where(
                            _RoleModel.id == record["role_id"]
                        )
                    )
                ).first()
                if role_exists is None:
                    raise IntegrityError(
                        f"Role {record['role_id']!r} does not exist"
                    )
                session.add(_RoleAssignmentModel(**known, extra=extra or None))
                await session.flush()
        return dict(record)

    async def query_role_assignments(
        self,
        *,
        user_id: Optional[str] = None,
        role_id: Optional[str] = None,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        self._require_engine()
        conditions = []
        if user_id is not None:
            conditions.append(_RoleAssignmentModel.user_id == user_id)
        if role_id is not None:
            conditions.append(_RoleAssignmentModel.role_id == role_id)
        if scope_type is not None:
            conditions.append(_RoleAssignmentModel.scope_type == scope_type)
        if scope_id is not None:
            conditions.append(_RoleAssignmentModel.scope_id == scope_id)
        async with self._session_factory() as session:  # type: ignore[misc]
            result = await session.execute(
                select(_RoleAssignmentModel)
                .where(*conditions)
                .order_by(
                    _RoleAssignmentModel.created_at, _RoleAssignmentModel.id
                )
            )
            return [_row_to_doc(r, _ASSIGNMENT_COLUMNS) for r in result.scalars()]

    async def delete_role_assignment(self, assignment_id: str) -> bool:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                result = await session.execute(
                    sa_delete(_RoleAssignmentModel).where(
                        _RoleAssignmentModel.id == assignment_id
                    )
                )
        return (result.rowcount or 0) > 0

    # -- api keys --------------------------------------------------------------------

    async def save_api_key(self, key_record: Dict[str, Any]) -> Dict[str, Any]:
        """Store an API key record; only the sha256 hash is persisted."""
        self._require_engine()
        if not isinstance(key_record, dict):
            raise ValueError("key_record must be a dict")
        if key_record.get("key") or key_record.get("api_key"):
            raise ValueError(
                "plaintext API keys must never be stored; pass key_hash (sha256)"
            )
        key_hash = key_record.get("key_hash")
        if not key_hash or not isinstance(key_hash, str):
            raise ValueError("key_record.key_hash (sha256 hex) is required")
        record = dict(key_record)
        record.setdefault("id", _new_id())
        record.setdefault("revoked", False)
        record["created_at"] = _iso_value(record.get("created_at"), _utcnow())
        known, extra = _split_known(record, _API_KEY_COLUMNS)
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                duplicate = (
                    await session.execute(
                        select(_ApiKeyModel.id).where(
                            _ApiKeyModel.key_hash == key_hash,
                            _ApiKeyModel.id != record["id"],
                        )
                    )
                ).first()
                if duplicate is not None:
                    raise IntegrityError(
                        "An API key with this hash already exists"
                    )
                try:
                    session.add(_ApiKeyModel(**known, extra=extra or None))
                    await session.flush()
                except SAIntegrityError as exc:
                    raise IntegrityError(
                        "An API key with this hash already exists"
                    ) from exc
        return dict(record)

    async def get_api_key_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            row = (
                await session.execute(
                    select(_ApiKeyModel).where(_ApiKeyModel.key_hash == key_hash)
                )
            ).scalar_one_or_none()
        return _row_to_doc(row, _API_KEY_COLUMNS) if row else None

    async def list_api_keys(self) -> List[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            result = await session.execute(
                select(_ApiKeyModel).order_by(
                    _ApiKeyModel.created_at, _ApiKeyModel.id
                )
            )
            return [_row_to_doc(r, _API_KEY_COLUMNS) for r in result.scalars()]

    async def revoke_api_key(self, key_id: str) -> bool:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                result = await session.execute(
                    sa_update(_ApiKeyModel)
                    .where(_ApiKeyModel.id == key_id)
                    .values(revoked=True, revoked_at=_iso(_utcnow()))
                )
        return (result.rowcount or 0) > 0

    # -- settings -----------------------------------------------------------------------

    async def get_setting(self, key: str) -> Any:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            row = (
                await session.execute(
                    select(_SettingModel.value).where(_SettingModel.key == key)
                )
            ).first()
        return row[0] if row is not None else None

    async def set_setting(self, key: str, value: Any) -> None:
        self._require_engine()
        if not key or not isinstance(key, str):
            raise ValueError("setting key must be a non-empty string")
        try:
            json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"setting value for {key!r} must be JSON-serializable"
            ) from exc
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                row = (
                    await session.execute(
                        select(_SettingModel).where(_SettingModel.key == key)
                    )
                ).scalar_one_or_none()
                if row is None:
                    session.add(_SettingModel(key=key, value=value))
                else:
                    row.value = value
                await session.flush()


    # -- SAML ---------------------------------------------------------------------------

    async def save_saml_request(
        self, request_id: str, data: Dict[str, Any], *, ttl_seconds: int
    ) -> None:
        """Store transient SAML request state with a TTL."""
        self._require_engine()
        if not request_id or not isinstance(request_id, str):
            raise ValueError("request_id must be a non-empty string")
        if not isinstance(data, dict):
            raise ValueError("data must be a dict")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        expires_at = time.time() + ttl_seconds
        async with self._kv_lock:
            async with self._session_factory() as session:  # type: ignore[misc]
                async with session.begin():
                    await session.execute(
                        sa_delete(_SamlRequestModel).where(
                            _SamlRequestModel.request_id == request_id
                        )
                    )
                    session.add(
                        _SamlRequestModel(
                            request_id=request_id, data=data, expires_at=expires_at
                        )
                    )

    async def consume_saml_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Atomic fetch-and-delete; exactly one consumer wins.

        PostgreSQL (and other RETURNING dialects) use ``DELETE ... RETURNING``
        as a single statement; SQLite falls back to select+delete inside one
        transaction guarded by the kv lock.
        """
        self._require_engine()
        assert self._engine is not None
        now_epoch = time.time()
        async with self._kv_lock:
            async with self._session_factory() as session:  # type: ignore[misc]
                async with session.begin():
                    if self._engine.dialect.name != "sqlite":
                        result = await session.execute(
                            sa_delete(_SamlRequestModel)
                            .where(
                                _SamlRequestModel.request_id == request_id,
                                _SamlRequestModel.expires_at > now_epoch,
                            )
                            .returning(_SamlRequestModel.data)
                        )
                        row = result.first()
                        return dict(row[0]) if row is not None else None
                    row = (
                        await session.execute(
                            select(_SamlRequestModel).where(
                                _SamlRequestModel.request_id == request_id,
                                _SamlRequestModel.expires_at > now_epoch,
                            )
                        )
                    ).scalar_one_or_none()
                    if row is None:
                        return None
                    await session.execute(
                        sa_delete(_SamlRequestModel).where(
                            _SamlRequestModel.request_id == request_id
                        )
                    )
                    return dict(row.data)

    async def save_saml_response_id(self, response_id: str, *, ttl_seconds: int) -> None:
        """Record a consumed ResponseID for replay protection."""
        self._require_engine()
        if not response_id or not isinstance(response_id, str):
            raise ValueError("response_id must be a non-empty string")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        expires_at = time.time() + ttl_seconds
        async with self._kv_lock:
            async with self._session_factory() as session:  # type: ignore[misc]
                async with session.begin():
                    await session.execute(
                        sa_delete(_SamlResponseIdModel).where(
                            _SamlResponseIdModel.response_id == response_id
                        )
                    )
                    session.add(
                        _SamlResponseIdModel(
                            response_id=response_id, expires_at=expires_at
                        )
                    )

    async def check_and_record_saml_response_id(self, response_id: str) -> bool:
        """Return ``True`` when fresh (and record it); ``False`` on replay."""
        self._require_engine()
        if not response_id or not isinstance(response_id, str):
            raise ValueError("response_id must be a non-empty string")
        now_epoch = time.time()
        async with self._kv_lock:
            async with self._session_factory() as session:  # type: ignore[misc]
                async with session.begin():
                    row = (
                        await session.execute(
                            select(_SamlResponseIdModel).where(
                                _SamlResponseIdModel.response_id == response_id
                            )
                        )
                    ).scalar_one_or_none()
                    if row is not None:
                        # Persistent entries never expire; TTL entries only
                        # block replays until their expiry passes.
                        if row.expires_at is None or row.expires_at > now_epoch:
                            return False
                        await session.execute(
                            sa_delete(_SamlResponseIdModel).where(
                                _SamlResponseIdModel.response_id == response_id
                            )
                        )
                    # No TTL parameter in the contract: ledger entry persists.
                    session.add(
                        _SamlResponseIdModel(
                            response_id=response_id, expires_at=None
                        )
                    )
                    return True

    async def save_saml_user_mapping(
        self, name_id: str, sp_entity_id: str, user_id: str
    ) -> None:
        self._require_engine()
        if not name_id or not sp_entity_id or not user_id:
            raise ValueError("name_id, sp_entity_id and user_id are required")
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                await session.execute(
                    sa_delete(_SamlUserMappingModel).where(
                        _SamlUserMappingModel.name_id == name_id,
                        _SamlUserMappingModel.sp_entity_id == sp_entity_id,
                    )
                )
                session.add(
                    _SamlUserMappingModel(
                        name_id=name_id, sp_entity_id=sp_entity_id, user_id=user_id
                    )
                )

    async def get_saml_user_mapping(
        self, name_id: str, sp_entity_id: str
    ) -> Optional[str]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            row = (
                await session.execute(
                    select(_SamlUserMappingModel.user_id).where(
                        _SamlUserMappingModel.name_id == name_id,
                        _SamlUserMappingModel.sp_entity_id == sp_entity_id,
                    )
                )
            ).first()
        return row[0] if row is not None else None

    # -- OIDC -----------------------------------------------------------------------------

    async def save_oidc_provider(self, provider: Dict[str, Any]) -> Dict[str, Any]:
        """Create an OIDC provider with unique issuer and slug."""
        self._require_engine()
        if not isinstance(provider, dict):
            raise ValueError("provider must be a dict")
        if not provider.get("issuer") or not provider.get("name"):
            raise ValueError("provider requires issuer and name")
        record = dict(provider)
        record.setdefault("id", _new_id())
        record.setdefault("slug", _slugify(str(record["name"])))
        record["slug"] = str(record["slug"]).lower()
        record["issuer"] = str(record["issuer"])
        record.setdefault("enabled", True)
        record["created_at"] = _iso_value(record.get("created_at"), _utcnow())
        known, extra = _split_known(record, _OIDC_COLUMNS)
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                issuer_conflict = (
                    await session.execute(
                        select(_OidcProviderModel.id).where(
                            _OidcProviderModel.issuer == record["issuer"]
                        )
                    )
                ).first()
                if issuer_conflict is not None:
                    raise IntegrityError(
                        f"An OIDC provider with issuer {record['issuer']!r} "
                        "already exists"
                    )
                slug_conflict = (
                    await session.execute(
                        select(_OidcProviderModel.id).where(
                            _OidcProviderModel.slug == record["slug"]
                        )
                    )
                ).first()
                if slug_conflict is not None:
                    raise IntegrityError(
                        f"An OIDC provider with slug {record['slug']!r} "
                        "already exists"
                    )
                try:
                    session.add(_OidcProviderModel(**known, extra=extra or None))
                    await session.flush()
                except SAIntegrityError as exc:
                    raise IntegrityError(
                        "OIDC provider issuer/slug conflicts with an existing "
                        "provider"
                    ) from exc
        return dict(record)

    async def get_oidc_provider(self, issuer_or_slug: str) -> Optional[Dict[str, Any]]:
        self._require_engine()
        async with self._session_factory() as session:  # type: ignore[misc]
            row = (
                await session.execute(
                    select(_OidcProviderModel).where(
                        (_OidcProviderModel.issuer == issuer_or_slug)
                        | (
                            func.lower(_OidcProviderModel.slug)
                            == str(issuer_or_slug).lower()
                        )
                    )
                )
            ).first()
        return _row_to_doc(row[0], _OIDC_COLUMNS) if row else None

    async def update_oidc_provider(
        self, identifier: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Whitelisted update; unknown keys raise ``ValueError``."""
        self._require_engine()
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        rejected = set(updates) - OIDC_UPDATABLE_FIELDS
        if rejected:
            raise ValueError(
                f"OIDC provider fields not updatable: {sorted(rejected)}"
            )
        async with self._session_factory() as session:  # type: ignore[misc]
            async with session.begin():
                row = (
                    await session.execute(
                        select(_OidcProviderModel).where(
                            (_OidcProviderModel.issuer == identifier)
                            | (
                                func.lower(_OidcProviderModel.slug)
                                == str(identifier).lower()
                            )
                        )
                    )
                ).scalar_one_or_none()
                if row is None:
                    return None
                new_issuer = updates.get("issuer")
                if new_issuer is not None and str(new_issuer) != row.issuer:
                    conflict = (
                        await session.execute(
                            select(_OidcProviderModel.id).where(
                                _OidcProviderModel.issuer == str(new_issuer),
                                _OidcProviderModel.id != row.id,
                            )
                        )
                    ).first()
                    if conflict is not None:
                        raise IntegrityError(
                            f"An OIDC provider with issuer {new_issuer!r} "
                            "already exists"
                        )
                    row.issuer = str(new_issuer)
                new_slug = updates.get("slug")
                if new_slug is not None and str(new_slug).lower() != row.slug:
                    candidate = str(new_slug).lower()
                    conflict = (
                        await session.execute(
                            select(_OidcProviderModel.id).where(
                                _OidcProviderModel.slug == candidate,
                                _OidcProviderModel.id != row.id,
                            )
                        )
                    ).first()
                    if conflict is not None:
                        raise IntegrityError(
                            f"An OIDC provider with slug {candidate!r} "
                            "already exists"
                        )
                    row.slug = candidate
                for key, value in updates.items():
                    if key in ("issuer", "slug"):
                        continue
                    setattr(row, key, value)
                row.updated_at = _iso(_utcnow())
                await session.flush()
                return _row_to_doc(row, _OIDC_COLUMNS)


def _invitation_token() -> str:
    """Cryptographically secure invitation token (§0.3)."""
    return secrets.token_urlsafe(32)
