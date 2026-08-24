"""MongoDB database implementing the full §4 contract (CONTRACTS.md).

Motor-based :class:`AbstractDatabase` implementation. Semantics mirror
:class:`~authy_package.db.memory.InMemoryDatabase`:

- Case-insensitive email/username lookups via stored lowercase-normalized
  fields (``email_lowercase`` / ``username_lowercase``) with unique sparse
  indexes; phone lookups are exact-match with a unique sparse index.
- Update paths whitelist ``$set`` keys; unknown keys and operator-style
  keys (``$...``) are rejected with ``ValueError``.
- SAML request consume and response-id recording are atomic
  (``find_one_and_delete`` / unique-``_id`` insert).
- ``revoke_session`` is an atomic conditional update
  (``status: "active"`` filter).
- Audit events carry ``checksum`` = sha256 over canonical JSON of the event
  WITHOUT db-assigned fields (``id``, ``sequence``, ``checksum``), with
  ``previous_checksum`` included in the checksummed payload (hash chain).
- Pagination uses ``skip``/``limit`` plus ``count_documents`` totals.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from authy_package.db.abstract_db import AbstractDatabase
from authy_package.db.memory import GENESIS_CHECKSUM, OIDC_UPDATABLE_FIELDS
from authy_package.errors import IntegrityError

try:  # pragma: no cover - trivial import guard
    from motor.motor_asyncio import AsyncIOMotorClient
    from pymongo import ASCENDING, IndexModel
    from pymongo.errors import DuplicateKeyError

    MOTOR_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without motor
    MOTOR_AVAILABLE = False
    DuplicateKeyError = None  # type: ignore[assignment,misc]

logger = logging.getLogger("authy.db.mongodb")

__all__ = ["MongoDB"]

#: Fields assigned by the database; excluded from the audit checksum payload.
_AUDIT_DB_ASSIGNED_FIELDS = frozenset({"id", "sequence", "checksum"})

#: Whitelisted $set keys per collection update path (no caller-key
#: interpolation beyond these sets; '$'-prefixed keys are always rejected).
USER_UPDATABLE_FIELDS = frozenset(
    {
        "username",
        "email",
        "phone",
        "hashed_password",
        "mfa_secret",
        "mfa_enabled",
        "is_active",
        "role",
    }
)
ORG_UPDATABLE_FIELDS = frozenset({"name", "slug"})
MEMBER_UPDATABLE_FIELDS = frozenset({"role"})
WEBHOOK_ENDPOINT_UPDATABLE_FIELDS = frozenset(
    {"url", "events", "enabled", "secret", "description"}
)

#: list_users() filters may only target these fields.
_USER_FILTERABLE = frozenset(
    {
        "id",
        "username",
        "email",
        "phone",
        "hashed_password",
        "mfa_enabled",
        "mfa_secret",
        "is_active",
        "role",
        "created_at",
        "updated_at",
    }
)


def _utcnow() -> datetime:
    """Timezone-aware UTC now (§0.5)."""
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime) -> datetime:
    """Attach UTC to naive datetimes so comparisons never raise."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _new_id() -> str:
    """Random id from the secrets module (§0.3)."""
    return secrets.token_hex(16)


def _canonical_json(payload: Dict[str, Any]) -> bytes:
    """Deterministic JSON encoding for audit checksums (memory.py-exact)."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _slugify(value: str) -> str:
    """Derive a URL-safe slug from a name (memory.py-exact)."""
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "org"


def _validate_update_keys(updates: Any, whitelist: frozenset) -> None:
    """Reject non-dicts, operator keys and keys outside the whitelist."""
    if not isinstance(updates, dict):
        raise ValueError("updates must be a dict")
    operator_keys = sorted(k for k in updates if str(k).startswith("$"))
    if operator_keys:
        raise ValueError(
            f"operator keys are not allowed in updates: {operator_keys}"
        )
    rejected = set(updates) - whitelist
    if rejected:
        raise ValueError(f"fields not updatable: {sorted(rejected)}")


def _public(doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Strip Mongo internals from a stored document."""
    if doc is None:
        return None
    doc.pop("_id", None)
    doc.pop("username_lowercase", None)
    doc.pop("email_lowercase", None)
    return doc


class MongoDB(AbstractDatabase):
    """Full-contract MongoDB database (motor).

    Args:
        config: A :class:`~authy_package.config.DatabaseConfig` (uses
            ``connection_string`` and ``db_name``), a plain MongoDB URL
            string, or a dict with ``url``/``db_name`` keys.
    """

    def __init__(self, config: Any = None) -> None:
        if not MOTOR_AVAILABLE:
            raise ImportError(
                "MongoDB requires motor ('pip install motor')"
            )
        url = "mongodb://localhost:27017"
        db_name = "authy"
        if isinstance(config, str):
            url = config
        elif isinstance(config, dict):
            url = config.get("url") or config.get("connection_string") or url
            db_name = config.get("db_name") or db_name
        elif config is not None:
            url = getattr(config, "connection_string", "") or url
            db_name = getattr(config, "db_name", None) or db_name
        self._url = url
        self._db_name = db_name
        self._client = None
        self._db = None
        # Serializes hash-chain appends (mirror of the in-memory lock).
        self._audit_lock = asyncio.Lock()

    # -- lifecycle -----------------------------------------------------------

    @property
    def client(self):
        """The underlying motor client (created by :meth:`connect`)."""
        return self._client

    def _require_db(self):
        if self._db is None:
            from authy_package.errors import DatabaseError

            raise DatabaseError(
                "MongoDB is not connected; call connect() first",
                code="not_connected",
            )
        return self._db

    async def connect(self) -> None:
        """Create the motor client and ensure all contract indexes."""
        if self._client is not None:
            return
        self._client = AsyncIOMotorClient(self._url)
        self._db = self._client[self._db_name]
        await self._ensure_indexes()
        logger.info("MongoDB connected (%s/%s)", self._url, self._db_name)

    async def _ensure_indexes(self) -> None:
        """Create uniqueness/TTL indexes for all contract collections."""
        db = self._db
        await db.users.create_indexes(
            [
                IndexModel("email_lowercase", unique=True, sparse=True),
                IndexModel("username_lowercase", unique=True, sparse=True),
                IndexModel("phone", unique=True, sparse=True),
            ]
        )
        await db.organizations.create_indexes(
            [IndexModel("slug", unique=True)]
        )
        await db.invitations.create_indexes(
            [
                IndexModel("token", unique=True, sparse=True),
                IndexModel("org_id"),
            ]
        )
        await db.audit_events.create_indexes(
            [
                IndexModel("sequence", unique=True),
                IndexModel("timestamp"),
                IndexModel([("event_type", ASCENDING), ("actor", ASCENDING)]),
            ]
        )
        await db.webhook_deliveries.create_indexes(
            [IndexModel([("endpoint_id", ASCENDING), ("created_at", ASCENDING)])]
        )
        await db.roles.create_indexes([IndexModel("name", unique=True)])
        await db.role_assignments.create_indexes(
            [IndexModel("user_id"), IndexModel("role_id")]
        )
        await db.api_keys.create_indexes([IndexModel("key_hash", unique=True)])
        # TTL indexes clean up expired ledgers; entries without expires_at
        # (persistent response ids) are never expired by MongoDB.
        await db.saml_requests.create_indexes(
            [IndexModel("expires_at", expireAfterSeconds=0)]
        )
        await db.saml_response_ids.create_indexes(
            [IndexModel("expires_at", expireAfterSeconds=0)]
        )
        await db.oidc_providers.create_indexes(
            [
                IndexModel("issuer", unique=True),
                IndexModel("slug", unique=True),
            ]
        )

    async def close(self) -> None:
        """Close the motor client."""
        if self._client is not None:
            self._client.close()
            self._client = None
            self._db = None

    async def health_check(self) -> bool:
        """Ping the server; ``True`` when it answers."""
        if self._client is None:
            return False
        try:
            await self._client.admin.command("ping")
            return True
        except Exception:  # noqa: BLE001 - health checks report, never raise
            logger.exception("MongoDB health check failed")
            return False

    # -- users ----------------------------------------------------------------

    async def _find_user_by_identifier_field(
        self,
        *,
        email: Optional[str] = None,
        username: Optional[str] = None,
        phone: Optional[str] = None,
        exclude_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        query: Dict[str, Any] = {}
        if email:
            query["email_lowercase"] = str(email).lower()
        elif username:
            query["username_lowercase"] = str(username).lower()
        elif phone:
            query["phone"] = str(phone)
        else:
            return None
        if exclude_id is not None:
            query["_id"] = {"$ne": exclude_id}
        return await self._db.users.find_one(query)

    async def _check_unique_identifiers(
        self,
        *,
        email: Optional[str] = None,
        username: Optional[str] = None,
        phone: Optional[str] = None,
        exclude_id: Optional[str] = None,
    ) -> None:
        if email:
            owner = await self._find_user_by_identifier_field(
                email=email, exclude_id=exclude_id
            )
            if owner is not None:
                raise IntegrityError(
                    f"A user with email {email!r} already exists"
                )
        if username:
            owner = await self._find_user_by_identifier_field(
                username=username, exclude_id=exclude_id
            )
            if owner is not None:
                raise IntegrityError(
                    f"A user with username {username!r} already exists"
                )
        if phone:
            owner = await self._find_user_by_identifier_field(
                phone=phone, exclude_id=exclude_id
            )
            if owner is not None:
                raise IntegrityError(
                    f"A user with phone {phone!r} already exists"
                )

    def _normalize_user_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Maintain the lowercase identifier fields used by unique indexes."""
        if record.get("email"):
            record["email_lowercase"] = str(record["email"]).lower()
        else:
            record.pop("email_lowercase", None)
        if record.get("username"):
            record["username_lowercase"] = str(record["username"]).lower()
        else:
            record.pop("username_lowercase", None)
        return record

    async def create_user(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """Create a user with unique email/username/phone enforcement."""
        self._require_db()
        if not isinstance(user, dict):
            raise ValueError("user must be a dict")
        record = copy.deepcopy(user)
        record.setdefault("id", _new_id())
        now = _utcnow()
        record.setdefault("created_at", now)
        record.setdefault("updated_at", now)
        record.setdefault("is_active", True)
        record.setdefault("mfa_enabled", False)
        record.setdefault("role", "user")
        record["_id"] = record["id"]
        self._normalize_user_record(record)
        await self._check_unique_identifiers(
            email=record.get("email"),
            username=record.get("username"),
            phone=record.get("phone"),
        )
        try:
            await self._db.users.insert_one(record)
        except DuplicateKeyError as exc:
            raise IntegrityError(
                "A user with one of these identifiers already exists"
            ) from exc
        return _public(copy.deepcopy(record))

    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        self._require_db()
        doc = await self._db.users.find_one({"_id": user_id})
        return _public(doc)

    async def get_user_by_identifier(
        self,
        *,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Look up one user; email/username are case-insensitive."""
        self._require_db()
        doc = None
        if email:
            doc = await self._find_user_by_identifier_field(email=email)
        if doc is None and username:
            doc = await self._find_user_by_identifier_field(username=username)
        if doc is None and phone:
            doc = await self._find_user_by_identifier_field(phone=phone)
        return _public(doc)

    async def update_user(
        self, user_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Whitelisted partial update; reindexes lowercase identifiers."""
        self._require_db()
        _validate_update_keys(updates, USER_UPDATABLE_FIELDS)
        existing = await self._db.users.find_one({"_id": user_id})
        if existing is None:
            return None
        await self._check_unique_identifiers(
            email=updates.get("email", existing.get("email")),
            username=updates.get("username", existing.get("username")),
            phone=updates.get("phone", existing.get("phone")),
            exclude_id=user_id,
        )
        set_fields = dict(updates)
        set_fields["updated_at"] = _utcnow()
        merged = {**existing, **set_fields}
        self._normalize_user_record(merged)
        set_fields.update(
            {
                k: merged[k]
                for k in ("email_lowercase", "username_lowercase")
                if k in merged
            }
        )
        try:
            await self._db.users.update_one(
                {"_id": user_id}, {"$set": set_fields}
            )
        except DuplicateKeyError as exc:
            raise IntegrityError(
                "A user with one of these identifiers already exists"
            ) from exc
        return _public(await self._db.users.find_one({"_id": user_id}))

    async def delete_user(self, user_id: str) -> bool:
        self._require_db()
        result = await self._db.users.delete_one({"_id": user_id})
        return result.deleted_count > 0

    async def list_users(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List users with pagination; returns ``(rows, total_matching)``."""
        self._require_db()
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        query: Dict[str, Any] = {}
        if search:
            needle = re.escape(search.lower())
            query["$or"] = [
                {"username_lowercase": {"$regex": needle}},
                {"email_lowercase": {"$regex": needle}},
            ]
        if filters:
            for key, expected in filters.items():
                if key not in _USER_FILTERABLE:
                    raise ValueError(
                        f"list_users filter {key!r} is not a filterable field"
                    )
                query["_id" if key == "id" else key] = expected
        total = await self._db.users.count_documents(query)
        cursor = (
            self._db.users.find(query)
            .sort([("created_at", ASCENDING), ("_id", ASCENDING)])
            .skip(offset)
            .limit(limit)
        )
        rows = [_public(doc) async for doc in cursor]
        return rows, total

    async def count_users(
        self,
        *,
        active_only: bool = False,
        mfa_enabled: Optional[bool] = None,
        created_since: Optional[datetime] = None,
    ) -> int:
        self._require_db()
        query: Dict[str, Any] = {}
        if active_only:
            query["is_active"] = True
        if mfa_enabled is not None:
            query["mfa_enabled"] = bool(mfa_enabled)
        if created_since is not None:
            query["created_at"] = {"$gte": _ensure_aware(created_since)}
        return await self._db.users.count_documents(query)

    # -- sessions ---------------------------------------------------------------

    async def save_session(self, session: Dict[str, Any]) -> None:
        """Insert or replace a session document."""
        self._require_db()
        if not isinstance(session, dict):
            raise ValueError("session must be a dict")
        if not session.get("user_id"):
            raise ValueError("session.user_id is required")
        record = copy.deepcopy(session)
        record.setdefault("id", _new_id())
        record.setdefault("status", "active")
        record.setdefault("created_at", _utcnow())
        record["_id"] = record["id"]
        await self._db.sessions.replace_one(
            {"_id": record["id"]}, record, upsert=True
        )

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        self._require_db()
        doc = await self._db.sessions.find_one({"_id": session_id})
        return _public(doc)

    async def get_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        self._require_db()
        cursor = self._db.sessions.find(
            {"user_id": user_id, "status": "active"}
        )
        return [_public(doc) async for doc in cursor]

    async def revoke_session(self, session_id: str) -> bool:
        """Atomic status flip: only the first revoke of an active session wins."""
        self._require_db()
        result = await self._db.sessions.update_one(
            {"_id": session_id, "status": "active"},
            {"$set": {"status": "revoked", "revoked_at": _utcnow()}},
        )
        return result.matched_count == 1

    async def revoke_all_user_sessions(self, user_id: str) -> int:
        self._require_db()
        result = await self._db.sessions.update_many(
            {"user_id": user_id, "status": "active"},
            {"$set": {"status": "revoked", "revoked_at": _utcnow()}},
        )
        return result.modified_count

    # -- organizations -------------------------------------------------------

    async def create_organization(self, org: Dict[str, Any]) -> Dict[str, Any]:
        """Create an organization with a unique slug."""
        self._require_db()
        if not isinstance(org, dict):
            raise ValueError("org must be a dict")
        record = copy.deepcopy(org)
        if not record.get("name"):
            raise ValueError("org.name is required")
        record.setdefault("id", _new_id())
        record.setdefault("slug", _slugify(str(record["name"])))
        record["slug"] = str(record["slug"]).lower()
        now = _utcnow()
        record.setdefault("created_at", now)
        record.setdefault("updated_at", record["created_at"])
        record["_id"] = record["id"]
        try:
            await self._db.organizations.insert_one(record)
        except DuplicateKeyError as exc:
            raise IntegrityError(
                f"An organization with slug {record['slug']!r} already exists"
            ) from exc
        return _public(copy.deepcopy(record))

    async def get_organization(self, org_id: str) -> Optional[Dict[str, Any]]:
        self._require_db()
        doc = await self._db.organizations.find_one({"_id": org_id})
        return _public(doc)

    async def get_organization_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        self._require_db()
        doc = await self._db.organizations.find_one(
            {"slug": str(slug).lower()}
        )
        return _public(doc)

    async def update_organization(
        self, org_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        self._require_db()
        _validate_update_keys(updates, ORG_UPDATABLE_FIELDS)
        existing = await self._db.organizations.find_one({"_id": org_id})
        if existing is None:
            return None
        set_fields = dict(updates)
        new_slug = updates.get("slug")
        if new_slug is not None:
            candidate = str(new_slug).lower()
            owner = await self._db.organizations.find_one(
                {"slug": candidate, "_id": {"$ne": org_id}}
            )
            if owner is not None:
                raise IntegrityError(
                    f"An organization with slug {candidate!r} already exists"
                )
            set_fields["slug"] = candidate
        set_fields["updated_at"] = _utcnow()
        try:
            await self._db.organizations.update_one(
                {"_id": org_id}, {"$set": set_fields}
            )
        except DuplicateKeyError as exc:
            raise IntegrityError(
                "Organization slug conflicts with another organization"
            ) from exc
        return _public(await self._db.organizations.find_one({"_id": org_id}))

    async def delete_organization(self, org_id: str) -> bool:
        """Delete an organization and its member/invitation links."""
        self._require_db()
        await self._db.org_members.delete_many({"org_id": org_id})
        await self._db.invitations.delete_many({"org_id": org_id})
        result = await self._db.organizations.delete_one({"_id": org_id})
        return result.deleted_count > 0

    async def list_organizations(
        self, *, limit: int = 50, offset: int = 0
    ) -> Tuple[List[Dict[str, Any]], int]:
        self._require_db()
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        total = await self._db.organizations.count_documents({})
        cursor = (
            self._db.organizations.find({})
            .sort([("created_at", ASCENDING), ("_id", ASCENDING)])
            .skip(offset)
            .limit(limit)
        )
        rows = [_public(doc) async for doc in cursor]
        return rows, total

    async def add_org_member(self, org_id: str, member: Dict[str, Any]) -> Dict[str, Any]:
        """Add a member to an organization."""
        self._require_db()
        if not isinstance(member, dict) or not member.get("user_id"):
            raise ValueError("member must be a dict with a user_id")
        org = await self._db.organizations.find_one({"_id": org_id})
        if org is None:
            raise IntegrityError(f"Organization {org_id!r} does not exist")
        record = copy.deepcopy(member)
        record["user_id"] = str(record["user_id"])
        record.setdefault("role", "member")
        record.setdefault("added_at", _utcnow())
        record["org_id"] = org_id
        record["_id"] = f"{org_id}\x00{record['user_id']}"
        try:
            await self._db.org_members.insert_one(record)
        except DuplicateKeyError as exc:
            raise IntegrityError(
                f"User {record['user_id']!r} is already a member of {org_id!r}"
            ) from exc
        return _public(copy.deepcopy(record))

    async def get_org_members(self, org_id: str) -> List[Dict[str, Any]]:
        self._require_db()
        cursor = self._db.org_members.find({"org_id": org_id}).sort(
            [("added_at", ASCENDING), ("user_id", ASCENDING)]
        )
        return [_public(doc) async for doc in cursor]

    async def update_org_member(
        self, org_id: str, user_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        self._require_db()
        _validate_update_keys(updates, MEMBER_UPDATABLE_FIELDS)
        result = await self._db.org_members.update_one(
            {"_id": f"{org_id}\x00{user_id}"}, {"$set": dict(updates)}
        )
        if result.matched_count == 0:
            return None
        doc = await self._db.org_members.find_one(
            {"_id": f"{org_id}\x00{user_id}"}
        )
        return _public(doc)

    async def remove_org_member(self, org_id: str, user_id: str) -> bool:
        self._require_db()
        result = await self._db.org_members.delete_one(
            {"_id": f"{org_id}\x00{user_id}"}
        )
        return result.deleted_count > 0

    async def create_invitation(self, invitation: Dict[str, Any]) -> Dict[str, Any]:
        """Create an org invitation (token generated when absent)."""
        self._require_db()
        if not isinstance(invitation, dict) or not invitation.get("org_id"):
            raise ValueError("invitation must be a dict with an org_id")
        org = await self._db.organizations.find_one({"_id": invitation["org_id"]})
        if org is None:
            raise IntegrityError(
                f"Organization {invitation['org_id']!r} does not exist"
            )
        record = copy.deepcopy(invitation)
        record.setdefault("id", _new_id())
        record.setdefault("token", secrets.token_urlsafe(32))
        record.setdefault("status", "pending")
        record.setdefault("created_at", _utcnow())
        record["_id"] = record["id"]
        await self._db.invitations.insert_one(record)
        return _public(copy.deepcopy(record))

    async def get_invitation_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        self._require_db()
        doc = await self._db.invitations.find_one({"token": token})
        return _public(doc)

    async def get_pending_invitations(self, org_id: str) -> List[Dict[str, Any]]:
        self._require_db()
        cursor = self._db.invitations.find(
            {"org_id": org_id, "status": "pending"}
        ).sort([("created_at", ASCENDING), ("_id", ASCENDING)])
        return [_public(doc) async for doc in cursor]

    async def delete_invitation(self, invitation_id: str) -> bool:
        self._require_db()
        result = await self._db.invitations.delete_one({"_id": invitation_id})
        return result.deleted_count > 0


    # -- audit log --------------------------------------------------------------

    @staticmethod
    def _audit_checksum(payload: Dict[str, Any], previous_checksum: str) -> str:
        """sha256 over canonical JSON incl. ``previous_checksum`` (hash chain)."""
        return hashlib.sha256(
            _canonical_json({**payload, "previous_checksum": previous_checksum})
        ).hexdigest()

    async def _append_audit_event(
        self, event: Dict[str, Any]
    ) -> Dict[str, Any]:
        if not isinstance(event, dict):
            raise ValueError("event must be a dict")
        last = (
            await self._db.audit_events.find({})
            .sort("sequence", -1)
            .limit(1)
            .to_dict(length=1)
        )
        previous_checksum = (
            last[0]["checksum"] if last else GENESIS_CHECKSUM
        )
        sequence = (last[0]["sequence"] + 1) if last else 1
        record = copy.deepcopy(event)
        record.setdefault("id", _new_id())
        record.setdefault("timestamp", _utcnow())
        payload = {
            key: value
            for key, value in record.items()
            if key not in _AUDIT_DB_ASSIGNED_FIELDS
        }
        payload["previous_checksum"] = previous_checksum
        checksum = self._audit_checksum(
            {k: v for k, v in payload.items() if k != "previous_checksum"},
            previous_checksum,
        )
        record["sequence"] = sequence
        record["checksum"] = checksum
        record["previous_checksum"] = previous_checksum
        record["_id"] = record["id"]
        await self._db.audit_events.insert_one(record)
        return _public(copy.deepcopy(record))

    async def save_audit_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Append one event to the hash chain."""
        self._require_db()
        async with self._audit_lock:
            return await self._append_audit_event(event)

    async def save_audit_events(self, events: List[Dict[str, Any]]) -> int:
        """Append events in order; all-or-nothing within this process."""
        self._require_db()
        if not isinstance(events, list):
            raise ValueError("events must be a list")
        async with self._audit_lock:
            for event in events:
                await self._append_audit_event(event)
        return len(events)

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
        self._require_db()
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        query: Dict[str, Any] = {}
        if event_types:
            query["event_type"] = {"$in": list(event_types)}
        if actor is not None:
            query["actor"] = actor
        if target is not None:
            query["target"] = target
        if start is not None or end is not None:
            range_query: Dict[str, Any] = {}
            if start is not None:
                range_query["$gte"] = _ensure_aware(start)
            if end is not None:
                range_query["$lte"] = _ensure_aware(end)
            query["timestamp"] = range_query
        total = await self._db.audit_events.count_documents(query)
        cursor = (
            self._db.audit_events.find(query)
            .sort([("timestamp", -1), ("sequence", -1)])
            .skip(offset)
            .limit(limit)
        )
        rows = [_public(doc) async for doc in cursor]
        return rows, total

    async def get_audit_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        self._require_db()
        doc = await self._db.audit_events.find_one({"_id": event_id})
        return _public(doc)

    async def delete_audit_events_before(self, ts: datetime) -> int:
        """Prune events older than ``ts``; returns the count deleted."""
        self._require_db()
        async with self._audit_lock:
            result = await self._db.audit_events.delete_many(
                {"timestamp": {"$lt": _ensure_aware(ts)}}
            )
        return result.deleted_count

    async def get_audit_statistics(
        self, *, since: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Aggregate audit statistics (totals, per-type, per-actor)."""
        self._require_db()
        query: Dict[str, Any] = {}
        if since is not None:
            query["timestamp"] = {"$gte": _ensure_aware(since)}
        cursor = self._db.audit_events.find(
            query, {"timestamp": 1, "event_type": 1, "actor": 1}
        )
        total = 0
        by_type: Dict[str, int] = {}
        by_actor: Dict[str, int] = {}
        first_at: Optional[datetime] = None
        last_at: Optional[datetime] = None
        async for doc in cursor:
            total += 1
            record = {
                key: value
                for key, value in (
                    ("event_type", doc.get("event_type")),
                    ("actor", doc.get("actor")),
                )
                if value is not None
            }
            type_key = str(record.get("event_type", "unknown"))
            actor_key = str(record.get("actor", "unknown"))
            by_type[type_key] = by_type.get(type_key, 0) + 1
            by_actor[actor_key] = by_actor.get(actor_key, 0) + 1
            when = _ensure_aware(doc["timestamp"])
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
        self._require_db()
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be positive")
        start = _ensure_aware(since)
        now = _utcnow()
        if start > now:
            return []
        cursor = self._db.audit_events.find(
            {"timestamp": {"$gte": start, "$lte": now}}, {"timestamp": 1}
        )
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
        async for doc in cursor:
            when = _ensure_aware(doc["timestamp"])
            index = int((when - start).total_seconds() // bucket_seconds)
            buckets[min(index, bucket_count - 1)]["count"] += 1
        return buckets

    # -- webhooks ----------------------------------------------------------------

    async def save_webhook_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Create a webhook endpoint record."""
        self._require_db()
        if not isinstance(endpoint, dict) or not endpoint.get("url"):
            raise ValueError("endpoint must be a dict with a url")
        record = copy.deepcopy(endpoint)
        record.setdefault("id", _new_id())
        record.setdefault("events", [])
        record.setdefault("enabled", True)
        record.setdefault("created_at", _utcnow())
        record["_id"] = record["id"]
        await self._db.webhook_endpoints.insert_one(record)
        return _public(copy.deepcopy(record))

    async def get_webhook_endpoint(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        self._require_db()
        doc = await self._db.webhook_endpoints.find_one({"_id": endpoint_id})
        return _public(doc)

    async def list_webhook_endpoints(self) -> List[Dict[str, Any]]:
        self._require_db()
        cursor = self._db.webhook_endpoints.find({}).sort(
            [("created_at", ASCENDING), ("_id", ASCENDING)]
        )
        return [_public(doc) async for doc in cursor]

    async def update_webhook_endpoint(
        self, endpoint_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        self._require_db()
        _validate_update_keys(updates, WEBHOOK_ENDPOINT_UPDATABLE_FIELDS)
        set_fields = dict(updates)
        set_fields["updated_at"] = _utcnow()
        result = await self._db.webhook_endpoints.update_one(
            {"_id": endpoint_id}, {"$set": set_fields}
        )
        if result.matched_count == 0:
            return None
        doc = await self._db.webhook_endpoints.find_one({"_id": endpoint_id})
        return _public(doc)

    async def delete_webhook_endpoint(self, endpoint_id: str) -> bool:
        """Delete an endpoint and its delivery history."""
        self._require_db()
        await self._db.webhook_deliveries.delete_many(
            {"endpoint_id": endpoint_id}
        )
        result = await self._db.webhook_endpoints.delete_one(
            {"_id": endpoint_id}
        )
        return result.deleted_count > 0

    async def save_webhook_delivery(self, delivery: Dict[str, Any]) -> Dict[str, Any]:
        """Record a delivery attempt for an endpoint."""
        self._require_db()
        if not isinstance(delivery, dict) or not delivery.get("endpoint_id"):
            raise ValueError("delivery must be a dict with an endpoint_id")
        endpoint = await self._db.webhook_endpoints.find_one(
            {"_id": delivery["endpoint_id"]}
        )
        if endpoint is None:
            raise IntegrityError(
                f"Webhook endpoint {delivery['endpoint_id']!r} does not exist"
            )
        record = copy.deepcopy(delivery)
        record.setdefault("id", _new_id())
        record.setdefault("created_at", _utcnow())
        record["_id"] = record["id"]
        await self._db.webhook_deliveries.insert_one(record)
        return _public(copy.deepcopy(record))

    async def get_webhook_deliveries(
        self, endpoint_id: str, *, limit: int = 50
    ) -> List[Dict[str, Any]]:
        self._require_db()
        if limit < 0:
            raise ValueError("limit must be non-negative")
        cursor = (
            self._db.webhook_deliveries.find({"endpoint_id": endpoint_id})
            .sort([("created_at", -1), ("_id", -1)])
            .limit(limit)
        )
        return [_public(doc) async for doc in cursor]

    # -- RBAC ---------------------------------------------------------------------

    async def save_role(self, role: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update a role (unique name)."""
        self._require_db()
        if not isinstance(role, dict) or not role.get("name"):
            raise ValueError("role must be a dict with a name")
        role_id = role.get("id")
        duplicate_query: Dict[str, Any] = {"name": role["name"]}
        if role_id:
            duplicate_query["_id"] = {"$ne": role_id}
        if await self._db.roles.find_one(duplicate_query) is not None:
            raise IntegrityError(
                f"A role named {role['name']!r} already exists"
            )
        record = copy.deepcopy(role)
        existing = (
            await self._db.roles.find_one({"_id": role_id}) if role_id else None
        )
        if existing is None:
            record.setdefault("id", _new_id())
            record.setdefault("created_at", _utcnow())
        else:
            record.setdefault("created_at", existing.get("created_at"))
        record.setdefault("permissions", [])
        record["updated_at"] = _utcnow()
        record["_id"] = record["id"]
        try:
            await self._db.roles.replace_one(
                {"_id": record["id"]}, record, upsert=True
            )
        except DuplicateKeyError as exc:
            raise IntegrityError(
                f"A role named {record['name']!r} already exists"
            ) from exc
        return _public(copy.deepcopy(record))

    async def get_role(self, role_id: str) -> Optional[Dict[str, Any]]:
        self._require_db()
        doc = await self._db.roles.find_one({"_id": role_id})
        return _public(doc)

    async def list_roles(self) -> List[Dict[str, Any]]:
        self._require_db()
        cursor = self._db.roles.find({}).sort(
            [("created_at", ASCENDING), ("_id", ASCENDING)]
        )
        return [_public(doc) async for doc in cursor]

    async def delete_role(self, role_id: str) -> bool:
        self._require_db()
        assignments = await self._db.role_assignments.count_documents(
            {"role_id": role_id}
        )
        if assignments:
            raise IntegrityError(
                f"Role {role_id!r} still has assignments; remove them first"
            )
        result = await self._db.roles.delete_one({"_id": role_id})
        return result.deleted_count > 0

    async def save_role_assignment(self, assignment: Dict[str, Any]) -> Dict[str, Any]:
        """Create a role assignment (role must exist)."""
        self._require_db()
        if not isinstance(assignment, dict):
            raise ValueError("assignment must be a dict")
        if not assignment.get("user_id") or not assignment.get("role_id"):
            raise ValueError("assignment requires user_id and role_id")
        role = await self._db.roles.find_one({"_id": assignment["role_id"]})
        if role is None:
            raise IntegrityError(
                f"Role {assignment['role_id']!r} does not exist"
            )
        record = copy.deepcopy(assignment)
        record.setdefault("id", _new_id())
        record.setdefault("created_at", _utcnow())
        record["_id"] = record["id"]
        await self._db.role_assignments.insert_one(record)
        return _public(copy.deepcopy(record))

    async def query_role_assignments(
        self,
        *,
        user_id: Optional[str] = None,
        role_id: Optional[str] = None,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        self._require_db()
        query: Dict[str, Any] = {}
        if user_id is not None:
            query["user_id"] = user_id
        if role_id is not None:
            query["role_id"] = role_id
        if scope_type is not None:
            query["scope_type"] = scope_type
        if scope_id is not None:
            query["scope_id"] = scope_id
        cursor = self._db.role_assignments.find(query).sort(
            [("created_at", ASCENDING), ("_id", ASCENDING)]
        )
        return [_public(doc) async for doc in cursor]

    async def delete_role_assignment(self, assignment_id: str) -> bool:
        self._require_db()
        result = await self._db.role_assignments.delete_one(
            {"_id": assignment_id}
        )
        return result.deleted_count > 0

    # -- api keys --------------------------------------------------------------------

    async def save_api_key(self, key_record: Dict[str, Any]) -> Dict[str, Any]:
        """Store an API key record; only the sha256 hash is persisted."""
        self._require_db()
        if not isinstance(key_record, dict):
            raise ValueError("key_record must be a dict")
        if key_record.get("key") or key_record.get("api_key"):
            raise ValueError(
                "plaintext API keys must never be stored; pass key_hash (sha256)"
            )
        key_hash = key_record.get("key_hash")
        if not key_hash or not isinstance(key_hash, str):
            raise ValueError("key_record.key_hash (sha256 hex) is required")
        record = copy.deepcopy(key_record)
        record.setdefault("id", _new_id())
        record.setdefault("revoked", False)
        record.setdefault("created_at", _utcnow())
        record["_id"] = record["id"]
        try:
            await self._db.api_keys.insert_one(record)
        except DuplicateKeyError as exc:
            raise IntegrityError(
                "An API key with this hash already exists"
            ) from exc
        return _public(copy.deepcopy(record))

    async def get_api_key_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        self._require_db()
        doc = await self._db.api_keys.find_one({"key_hash": key_hash})
        return _public(doc)

    async def list_api_keys(self) -> List[Dict[str, Any]]:
        self._require_db()
        cursor = self._db.api_keys.find({}).sort(
            [("created_at", ASCENDING), ("_id", ASCENDING)]
        )
        return [_public(doc) async for doc in cursor]

    async def revoke_api_key(self, key_id: str) -> bool:
        self._require_db()
        result = await self._db.api_keys.update_one(
            {"_id": key_id},
            {"$set": {"revoked": True, "revoked_at": _utcnow()}},
        )
        return result.matched_count > 0

    # -- settings -----------------------------------------------------------------------

    async def get_setting(self, key: str) -> Any:
        self._require_db()
        doc = await self._db.settings.find_one({"_id": key})
        if doc is None:
            return None
        return copy.deepcopy(doc.get("value"))

    async def set_setting(self, key: str, value: Any) -> None:
        self._require_db()
        if not key or not isinstance(key, str):
            raise ValueError("setting key must be a non-empty string")
        try:
            json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"setting value for {key!r} must be JSON-serializable"
            ) from exc
        await self._db.settings.replace_one(
            {"_id": key}, {"_id": key, "value": copy.deepcopy(value)}, upsert=True
        )


    # -- SAML ---------------------------------------------------------------------------

    async def save_saml_request(
        self, request_id: str, data: Dict[str, Any], *, ttl_seconds: int
    ) -> None:
        """Store transient SAML request state with a TTL."""
        self._require_db()
        if not request_id or not isinstance(request_id, str):
            raise ValueError("request_id must be a non-empty string")
        if not isinstance(data, dict):
            raise ValueError("data must be a dict")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        expires_at = _utcnow().timestamp() + ttl_seconds
        await self._db.saml_requests.replace_one(
            {"_id": request_id},
            {
                "_id": request_id,
                "data": copy.deepcopy(data),
                "expires_at": datetime.fromtimestamp(expires_at, tz=timezone.utc),
            },
            upsert=True,
        )

    async def consume_saml_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Atomic fetch-and-delete; exactly one consumer wins."""
        self._require_db()
        doc = await self._db.saml_requests.find_one_and_delete(
            {"_id": request_id, "expires_at": {"$gt": _utcnow()}}
        )
        if doc is None:
            return None
        return copy.deepcopy(doc.get("data"))

    async def save_saml_response_id(self, response_id: str, *, ttl_seconds: int) -> None:
        """Record a consumed ResponseID for replay protection."""
        self._require_db()
        if not response_id or not isinstance(response_id, str):
            raise ValueError("response_id must be a non-empty string")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        expires_at = _utcnow().timestamp() + ttl_seconds
        await self._db.saml_response_ids.replace_one(
            {"_id": response_id},
            {
                "_id": response_id,
                "expires_at": datetime.fromtimestamp(expires_at, tz=timezone.utc),
            },
            upsert=True,
        )

    async def check_and_record_saml_response_id(self, response_id: str) -> bool:
        """Return ``True`` when fresh (and record it); ``False`` on replay."""
        self._require_db()
        if not response_id or not isinstance(response_id, str):
            raise ValueError("response_id must be a non-empty string")
        # Expired TTL entries no longer block; persistent entries (no
        # expires_at) block forever.
        await self._db.saml_response_ids.find_one_and_delete(
            {"_id": response_id, "expires_at": {"$lte": _utcnow()}}
        )
        try:
            # No TTL parameter in the contract: the ledger entry persists
            # (no expires_at field, so the TTL index never touches it).
            await self._db.saml_response_ids.insert_one(
                {"_id": response_id, "recorded_at": _utcnow()}
            )
            return True
        except DuplicateKeyError:
            return False

    async def save_saml_user_mapping(
        self, name_id: str, sp_entity_id: str, user_id: str
    ) -> None:
        self._require_db()
        if not name_id or not sp_entity_id or not user_id:
            raise ValueError("name_id, sp_entity_id and user_id are required")
        await self._db.saml_user_mappings.replace_one(
            {"_id": f"{name_id}\x00{sp_entity_id}"},
            {
                "_id": f"{name_id}\x00{sp_entity_id}",
                "name_id": name_id,
                "sp_entity_id": sp_entity_id,
                "user_id": user_id,
            },
            upsert=True,
        )

    async def get_saml_user_mapping(
        self, name_id: str, sp_entity_id: str
    ) -> Optional[str]:
        self._require_db()
        doc = await self._db.saml_user_mappings.find_one(
            {"_id": f"{name_id}\x00{sp_entity_id}"}
        )
        return doc.get("user_id") if doc else None

    # -- OIDC -----------------------------------------------------------------------------

    async def save_oidc_provider(self, provider: Dict[str, Any]) -> Dict[str, Any]:
        """Create an OIDC provider with unique issuer and slug."""
        self._require_db()
        if not isinstance(provider, dict):
            raise ValueError("provider must be a dict")
        if not provider.get("issuer") or not provider.get("name"):
            raise ValueError("provider requires issuer and name")
        issuer = str(provider["issuer"])
        record = copy.deepcopy(provider)
        record.setdefault("id", _new_id())
        record.setdefault("slug", _slugify(str(record["name"])))
        record["slug"] = str(record["slug"]).lower()
        record["issuer"] = issuer
        record.setdefault("enabled", True)
        record.setdefault("created_at", _utcnow())
        record["_id"] = record["id"]
        if await self._db.oidc_providers.find_one({"issuer": issuer}) is not None:
            raise IntegrityError(
                f"An OIDC provider with issuer {issuer!r} already exists"
            )
        if (
            await self._db.oidc_providers.find_one({"slug": record["slug"]})
            is not None
        ):
            raise IntegrityError(
                f"An OIDC provider with slug {record['slug']!r} already exists"
            )
        try:
            await self._db.oidc_providers.insert_one(record)
        except DuplicateKeyError as exc:
            raise IntegrityError(
                "OIDC provider issuer/slug conflicts with an existing provider"
            ) from exc
        return _public(copy.deepcopy(record))

    async def get_oidc_provider(self, issuer_or_slug: str) -> Optional[Dict[str, Any]]:
        self._require_db()
        doc = await self._db.oidc_providers.find_one(
            {
                "$or": [
                    {"issuer": issuer_or_slug},
                    {"slug": str(issuer_or_slug).lower()},
                ]
            }
        )
        return _public(doc)

    async def update_oidc_provider(
        self, identifier: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Whitelisted update; unknown keys raise ``ValueError``."""
        self._require_db()
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        rejected = set(updates) - OIDC_UPDATABLE_FIELDS
        if rejected:
            raise ValueError(
                f"OIDC provider fields not updatable: {sorted(rejected)}"
            )
        existing = await self._db.oidc_providers.find_one(
            {
                "$or": [
                    {"issuer": identifier},
                    {"slug": str(identifier).lower()},
                ]
            }
        )
        if existing is None:
            return None
        set_fields = dict(updates)
        new_issuer = updates.get("issuer")
        if new_issuer is not None and str(new_issuer) != existing["issuer"]:
            conflict = await self._db.oidc_providers.find_one(
                {"issuer": str(new_issuer), "_id": {"$ne": existing["_id"]}}
            )
            if conflict is not None:
                raise IntegrityError(
                    f"An OIDC provider with issuer {new_issuer!r} already exists"
                )
            set_fields["issuer"] = str(new_issuer)
        new_slug = updates.get("slug")
        if new_slug is not None and str(new_slug).lower() != existing["slug"]:
            candidate = str(new_slug).lower()
            conflict = await self._db.oidc_providers.find_one(
                {"slug": candidate, "_id": {"$ne": existing["_id"]}}
            )
            if conflict is not None:
                raise IntegrityError(
                    f"An OIDC provider with slug {candidate!r} already exists"
                )
            set_fields["slug"] = candidate
        set_fields["updated_at"] = _utcnow()
        try:
            await self._db.oidc_providers.update_one(
                {"_id": existing["_id"]}, {"$set": set_fields}
            )
        except DuplicateKeyError as exc:
            raise IntegrityError(
                "OIDC provider issuer/slug conflicts with an existing provider"
            ) from exc
        doc = await self._db.oidc_providers.find_one({"_id": existing["_id"]})
        return _public(doc)
