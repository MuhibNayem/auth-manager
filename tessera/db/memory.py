"""In-memory database implementing the full §4 contract (CONTRACTS.md).

Dict-based implementation for tests and development. Notable semantics:

- Case-insensitive email/username lookups (indexes keyed on lower-cased
  values); phone lookups are exact-match.
- Audit events carry ``checksum`` = sha256 over canonical JSON of the event
  WITHOUT db-assigned fields (``id``, ``sequence``, ``checksum``), and the
  hash chain includes ``previous_checksum`` in the checksummed payload.
  :meth:`InMemoryDatabase.verify_audit_chain` re-verifies the whole chain.
- SAML request consume and response-id recording are atomic (asyncio lock +
  fetch-and-delete) so replay/reuse races resolve to a single winner.
- ``revoke_session`` is an atomic status flip guarded by the same lock.
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

from tessera.db.abstract_db import AbstractDatabase
from tessera.errors import IntegrityError

logger = logging.getLogger("tessera.db.memory")

__all__ = ["InMemoryDatabase"]

#: Sentinel previous checksum for the first audit event in the chain.
GENESIS_CHECKSUM = "0" * 64

#: Fields assigned by the database; excluded from the audit checksum payload.
_AUDIT_DB_ASSIGNED_FIELDS = frozenset({"id", "sequence", "checksum"})

#: Columns updatable on OIDC providers (§4 whitelist; no caller-key
#: interpolation beyond this set).
OIDC_UPDATABLE_FIELDS = frozenset(
    {
        "name",
        "display_name",
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
    }
)


def _utcnow() -> datetime:
    """Timezone-aware UTC now (§0.5)."""
    return datetime.now(timezone.utc)


def _new_id() -> str:
    """Random id from the secrets module (§0.3)."""
    return secrets.token_hex(16)


def _canonical_json(payload: Dict[str, Any]) -> bytes:
    """Deterministic JSON encoding for checksums."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _slugify(value: str) -> str:
    """Derive a URL-safe slug from a name."""
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "org"


def _ensure_aware(dt: datetime) -> datetime:
    """Attach UTC to naive datetimes so comparisons never raise."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class InMemoryDatabase(AbstractDatabase):
    """Full-contract in-memory database for tests and development."""

    def __init__(self) -> None:
        self._connected = False
        self._lock = asyncio.Lock()

        # users
        self._users: Dict[str, Dict[str, Any]] = {}
        self._users_by_email: Dict[str, str] = {}
        self._users_by_username: Dict[str, str] = {}
        self._users_by_phone: Dict[str, str] = {}

        # sessions
        self._sessions: Dict[str, Dict[str, Any]] = {}

        # organizations
        self._orgs: Dict[str, Dict[str, Any]] = {}
        self._orgs_by_slug: Dict[str, str] = {}
        self._org_members: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._invitations: Dict[str, Dict[str, Any]] = {}

        # audit
        self._audit_chain: List[Dict[str, Any]] = []
        self._audit_by_id: Dict[str, Dict[str, Any]] = {}

        # webhooks
        self._webhook_endpoints: Dict[str, Dict[str, Any]] = {}
        self._webhook_deliveries: List[Dict[str, Any]] = []

        # rbac
        self._roles: Dict[str, Dict[str, Any]] = {}
        self._role_assignments: Dict[str, Dict[str, Any]] = {}

        # api keys
        self._api_keys: Dict[str, Dict[str, Any]] = {}
        self._api_keys_by_hash: Dict[str, str] = {}

        # settings
        self._settings: Dict[str, Any] = {}

        # saml
        self._saml_requests: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._saml_response_ids: Dict[str, Optional[float]] = {}
        self._saml_user_mappings: Dict[Tuple[str, str], str] = {}

        # oidc
        self._oidc_providers: Dict[str, Dict[str, Any]] = {}
        self._oidc_by_issuer: Dict[str, str] = {}
        self._oidc_by_slug: Dict[str, str] = {}

    # -- lifecycle -----------------------------------------------------------

    async def connect(self) -> None:
        """Mark the database as connected (no-op backend)."""
        self._connected = True

    async def close(self) -> None:
        """Mark the database as closed."""
        self._connected = False

    async def health_check(self) -> bool:
        """The in-memory backend is always reachable."""
        return True

    # -- users ----------------------------------------------------------------

    def _index_user(self, user: Dict[str, Any]) -> None:
        email = user.get("email")
        username = user.get("username")
        phone = user.get("phone")
        if email:
            self._users_by_email[str(email).lower()] = user["id"]
        if username:
            self._users_by_username[str(username).lower()] = user["id"]
        if phone:
            self._users_by_phone[str(phone)] = user["id"]

    def _unindex_user(self, user: Dict[str, Any]) -> None:
        for index, field in (
            (self._users_by_email, "email"),
            (self._users_by_username, "username"),
            (self._users_by_phone, "phone"),
        ):
            value = user.get(field)
            if not value:
                continue
            key = str(value).lower() if field != "phone" else str(value)
            if index.get(key) == user["id"]:
                del index[key]

    def _check_unique_identifiers(
        self,
        *,
        email: Optional[str] = None,
        username: Optional[str] = None,
        phone: Optional[str] = None,
        exclude_user_id: Optional[str] = None,
    ) -> None:
        if email:
            owner = self._users_by_email.get(str(email).lower())
            if owner and owner != exclude_user_id:
                raise IntegrityError(f"A user with email {email!r} already exists")
        if username:
            owner = self._users_by_username.get(str(username).lower())
            if owner and owner != exclude_user_id:
                raise IntegrityError(
                    f"A user with username {username!r} already exists"
                )
        if phone:
            owner = self._users_by_phone.get(str(phone))
            if owner and owner != exclude_user_id:
                raise IntegrityError(f"A user with phone {phone!r} already exists")

    async def create_user(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """Create a user with unique email/username/phone enforcement."""
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

        self._check_unique_identifiers(
            email=record.get("email"),
            username=record.get("username"),
            phone=record.get("phone"),
        )
        self._users[record["id"]] = record
        self._index_user(record)
        logger.debug("Created user %s", record["id"])
        return copy.deepcopy(record)

    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        record = self._users.get(user_id)
        return copy.deepcopy(record) if record else None

    async def get_user_by_identifier(
        self,
        *,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Look up one user; email/username are case-insensitive."""
        user_id: Optional[str] = None
        if email:
            user_id = self._users_by_email.get(str(email).lower())
        if user_id is None and username:
            user_id = self._users_by_username.get(str(username).lower())
        if user_id is None and phone:
            user_id = self._users_by_phone.get(str(phone))
        if user_id is None:
            return None
        return copy.deepcopy(self._users[user_id])

    async def update_user(
        self, user_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        record = self._users.get(user_id)
        if record is None:
            return None
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        if "id" in updates or "created_at" in updates:
            raise ValueError("id and created_at are immutable")

        self._check_unique_identifiers(
            email=updates.get("email", record.get("email")),
            username=updates.get("username", record.get("username")),
            phone=updates.get("phone", record.get("phone")),
            exclude_user_id=user_id,
        )
        self._unindex_user(record)
        record.update(copy.deepcopy(updates))
        record["updated_at"] = _utcnow()
        self._index_user(record)
        return copy.deepcopy(record)

    async def delete_user(self, user_id: str) -> bool:
        record = self._users.pop(user_id, None)
        if record is None:
            return False
        self._unindex_user(record)
        return True

    def _user_matches(
        self,
        record: Dict[str, Any],
        search: Optional[str],
        filters: Optional[Dict[str, Any]],
    ) -> bool:
        if search:
            needle = search.lower()
            haystack = " ".join(
                str(record.get(field, "")) for field in ("username", "email")
            ).lower()
            if needle not in haystack:
                return False
        if filters:
            for key, expected in filters.items():
                if record.get(key) != expected:
                    return False
        return True

    async def list_users(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        matching = [
            record
            for record in sorted(
                self._users.values(), key=lambda r: r.get("created_at") or datetime.min.replace(tzinfo=timezone.utc)
            )
            if self._user_matches(record, search, filters)
        ]
        rows = [copy.deepcopy(r) for r in matching[offset : offset + limit]]
        return rows, len(matching)

    async def count_users(
        self,
        *,
        active_only: bool = False,
        mfa_enabled: Optional[bool] = None,
        created_since: Optional[datetime] = None,
    ) -> int:
        count = 0
        since = _ensure_aware(created_since) if created_since else None
        for record in self._users.values():
            if active_only and not record.get("is_active"):
                continue
            if mfa_enabled is not None and bool(record.get("mfa_enabled")) != mfa_enabled:
                continue
            if since is not None:
                created = record.get("created_at")
                if created is None or _ensure_aware(created) < since:
                    continue
            count += 1
        return count

    # -- sessions ---------------------------------------------------------------

    async def save_session(self, session: Dict[str, Any]) -> None:
        """Insert or replace a session document."""
        if not isinstance(session, dict):
            raise ValueError("session must be a dict")
        if not session.get("user_id"):
            raise ValueError("session.user_id is required")
        record = copy.deepcopy(session)
        record.setdefault("id", _new_id())
        record.setdefault("status", "active")
        record.setdefault("created_at", _utcnow())
        self._sessions[record["id"]] = record

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        record = self._sessions.get(session_id)
        return copy.deepcopy(record) if record else None

    async def get_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        return [
            copy.deepcopy(record)
            for record in self._sessions.values()
            if record.get("user_id") == user_id and record.get("status") == "active"
        ]

    async def revoke_session(self, session_id: str) -> bool:
        """Atomic status flip: only the first revoke of an active session wins."""
        async with self._lock:
            record = self._sessions.get(session_id)
            if record is None or record.get("status") != "active":
                return False
            record["status"] = "revoked"
            record["revoked_at"] = _utcnow()
            return True

    async def revoke_all_user_sessions(self, user_id: str) -> int:
        revoked = 0
        async with self._lock:
            for record in self._sessions.values():
                if record.get("user_id") == user_id and record.get("status") == "active":
                    record["status"] = "revoked"
                    record["revoked_at"] = _utcnow()
                    revoked += 1
        return revoked


    # -- organizations -------------------------------------------------------

    async def create_organization(self, org: Dict[str, Any]) -> Dict[str, Any]:
        """Create an organization with a unique slug."""
        if not isinstance(org, dict):
            raise ValueError("org must be a dict")
        record = copy.deepcopy(org)
        record.setdefault("id", _new_id())
        if not record.get("name"):
            raise ValueError("org.name is required")
        record.setdefault("slug", _slugify(str(record["name"])))
        slug = str(record["slug"]).lower()
        if slug in self._orgs_by_slug:
            raise IntegrityError(f"An organization with slug {slug!r} already exists")
        record["slug"] = slug
        record.setdefault("created_at", _utcnow())
        record.setdefault("updated_at", record["created_at"])
        self._orgs[record["id"]] = record
        self._orgs_by_slug[slug] = record["id"]
        self._org_members.setdefault(record["id"], {})
        return copy.deepcopy(record)

    async def get_organization(self, org_id: str) -> Optional[Dict[str, Any]]:
        record = self._orgs.get(org_id)
        return copy.deepcopy(record) if record else None

    async def get_organization_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        org_id = self._orgs_by_slug.get(str(slug).lower())
        if org_id is None:
            return None
        return copy.deepcopy(self._orgs[org_id])

    async def update_organization(
        self, org_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        record = self._orgs.get(org_id)
        if record is None:
            return None
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        if "id" in updates:
            raise ValueError("id is immutable")
        new_slug = updates.get("slug")
        if new_slug is not None:
            candidate = str(new_slug).lower()
            owner = self._orgs_by_slug.get(candidate)
            if owner and owner != org_id:
                raise IntegrityError(
                    f"An organization with slug {candidate!r} already exists"
                )
            del self._orgs_by_slug[record["slug"]]
            record["slug"] = candidate
            self._orgs_by_slug[candidate] = org_id
        record.update({k: copy.deepcopy(v) for k, v in updates.items() if k != "slug"})
        record["updated_at"] = _utcnow()
        return copy.deepcopy(record)

    async def delete_organization(self, org_id: str) -> bool:
        record = self._orgs.pop(org_id, None)
        if record is None:
            return False
        self._orgs_by_slug.pop(record["slug"], None)
        self._org_members.pop(org_id, None)
        self._invitations = {
            inv_id: inv
            for inv_id, inv in self._invitations.items()
            if inv.get("org_id") != org_id
        }
        return True

    async def list_organizations(
        self, *, limit: int = 50, offset: int = 0
    ) -> Tuple[List[Dict[str, Any]], int]:
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        ordered = sorted(self._orgs.values(), key=lambda r: r.get("created_at"))
        rows = [copy.deepcopy(r) for r in ordered[offset : offset + limit]]
        return rows, len(ordered)

    async def add_org_member(self, org_id: str, member: Dict[str, Any]) -> Dict[str, Any]:
        """Add a member to an organization."""
        if org_id not in self._orgs:
            raise IntegrityError(f"Organization {org_id!r} does not exist")
        if not isinstance(member, dict) or not member.get("user_id"):
            raise ValueError("member must be a dict with a user_id")
        members = self._org_members.setdefault(org_id, {})
        user_id = str(member["user_id"])
        if user_id in members:
            raise IntegrityError(f"User {user_id!r} is already a member of {org_id!r}")
        record = copy.deepcopy(member)
        record.setdefault("role", "member")
        record.setdefault("added_at", _utcnow())
        members[user_id] = record
        return copy.deepcopy(record)

    async def get_org_members(self, org_id: str) -> List[Dict[str, Any]]:
        members = self._org_members.get(org_id, {})
        ordered = sorted(members.values(), key=lambda r: r.get("added_at"))
        return [copy.deepcopy(r) for r in ordered]

    async def update_org_member(
        self, org_id: str, user_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        members = self._org_members.get(org_id, {})
        record = members.get(str(user_id))
        if record is None:
            return None
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        if "user_id" in updates:
            raise ValueError("user_id is immutable")
        record.update(copy.deepcopy(updates))
        return copy.deepcopy(record)

    async def remove_org_member(self, org_id: str, user_id: str) -> bool:
        members = self._org_members.get(org_id, {})
        return members.pop(str(user_id), None) is not None

    async def create_invitation(self, invitation: Dict[str, Any]) -> Dict[str, Any]:
        """Create an org invitation (token generated when absent)."""
        if not isinstance(invitation, dict) or not invitation.get("org_id"):
            raise ValueError("invitation must be a dict with an org_id")
        if invitation["org_id"] not in self._orgs:
            raise IntegrityError(f"Organization {invitation['org_id']!r} does not exist")
        record = copy.deepcopy(invitation)
        record.setdefault("id", _new_id())
        record.setdefault("token", secrets.token_urlsafe(32))
        record.setdefault("status", "pending")
        record.setdefault("created_at", _utcnow())
        self._invitations[record["id"]] = record
        return copy.deepcopy(record)

    async def get_invitation_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        for record in self._invitations.values():
            if record.get("token") == token:
                return copy.deepcopy(record)
        return None

    async def get_pending_invitations(self, org_id: str) -> List[Dict[str, Any]]:
        return [
            copy.deepcopy(record)
            for record in sorted(
                self._invitations.values(), key=lambda r: r.get("created_at")
            )
            if record.get("org_id") == org_id and record.get("status") == "pending"
        ]

    async def delete_invitation(self, invitation_id: str) -> bool:
        return self._invitations.pop(invitation_id, None) is not None

    # -- audit log --------------------------------------------------------------

    def _compute_audit_checksum(
        self, record: Dict[str, Any], previous_checksum: str
    ) -> str:
        """sha256 over canonical JSON of the event minus db-assigned fields.

        ``previous_checksum`` is part of the checksummed payload (hash chain).
        """
        payload = {
            key: value
            for key, value in record.items()
            if key not in _AUDIT_DB_ASSIGNED_FIELDS
        }
        payload["previous_checksum"] = previous_checksum
        return hashlib.sha256(_canonical_json(payload)).hexdigest()

    def _append_audit_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(event, dict):
            raise ValueError("event must be a dict")
        record = copy.deepcopy(event)
        record.setdefault("id", _new_id())
        record.setdefault("timestamp", _utcnow())
        record.setdefault("sequence", len(self._audit_chain) + 1)
        previous_checksum = (
            self._audit_chain[-1]["checksum"] if self._audit_chain else GENESIS_CHECKSUM
        )
        record["checksum"] = self._compute_audit_checksum(record, previous_checksum)
        record["previous_checksum"] = previous_checksum
        self._audit_chain.append(record)
        self._audit_by_id[record["id"]] = record
        return copy.deepcopy(record)

    async def save_audit_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Append one event to the hash chain."""
        async with self._lock:
            return self._append_audit_event(event)

    async def save_audit_events(self, events: List[Dict[str, Any]]) -> int:
        """Append events in order; all-or-nothing within this process."""
        if not isinstance(events, list):
            raise ValueError("events must be a list")
        async with self._lock:
            for event in events:
                self._append_audit_event(event)
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
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        start_aware = _ensure_aware(start) if start else None
        end_aware = _ensure_aware(end) if end else None
        type_filter = set(event_types) if event_types else None

        matching: List[Dict[str, Any]] = []
        for record in self._audit_chain:
            if type_filter is not None and record.get("event_type") not in type_filter:
                continue
            if actor is not None and record.get("actor") != actor:
                continue
            if target is not None and record.get("target") != target:
                continue
            timestamp = _ensure_aware(record.get("timestamp"))
            if start_aware is not None and timestamp < start_aware:
                continue
            if end_aware is not None and timestamp > end_aware:
                continue
            matching.append(record)

        matching.sort(key=lambda r: r.get("timestamp"), reverse=True)
        rows = [copy.deepcopy(r) for r in matching[offset : offset + limit]]
        return rows, len(matching)

    async def get_audit_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        record = self._audit_by_id.get(event_id)
        return copy.deepcopy(record) if record else None

    async def delete_audit_events_before(self, ts: datetime) -> int:
        """Prune events older than ``ts``.

        The oldest remaining event keeps its original ``previous_checksum``;
        chain verification treats it as the new genesis.
        """
        cutoff = _ensure_aware(ts)
        async with self._lock:
            before = len(self._audit_chain)
            kept = [
                record
                for record in self._audit_chain
                if _ensure_aware(record.get("timestamp")) >= cutoff
            ]
            self._audit_chain = kept
            self._audit_by_id = {record["id"]: record for record in kept}
            return before - len(kept)

    async def get_audit_statistics(
        self, *, since: Optional[datetime] = None
    ) -> Dict[str, Any]:
        since_aware = _ensure_aware(since) if since else None
        total = 0
        by_type: Dict[str, int] = {}
        by_actor: Dict[str, int] = {}
        first_at: Optional[datetime] = None
        last_at: Optional[datetime] = None
        for record in self._audit_chain:
            timestamp = _ensure_aware(record.get("timestamp"))
            if since_aware is not None and timestamp < since_aware:
                continue
            total += 1
            event_type = str(record.get("event_type", "unknown"))
            by_type[event_type] = by_type.get(event_type, 0) + 1
            actor_value = str(record.get("actor", "unknown"))
            by_actor[actor_value] = by_actor.get(actor_value, 0) + 1
            if first_at is None or timestamp < first_at:
                first_at = timestamp
            if last_at is None or timestamp > last_at:
                last_at = timestamp
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
        """Counts per fixed bucket from ``since`` until now (UTC)."""
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be positive")
        start = _ensure_aware(since)
        now = _utcnow()
        if start > now:
            return []
        bucket_count = int((now - start).total_seconds() // bucket_seconds) + 1
        buckets = [
            {"bucket_start": datetime.fromtimestamp(start.timestamp() + i * bucket_seconds, tz=timezone.utc), "count": 0}
            for i in range(bucket_count)
        ]
        for record in self._audit_chain:
            timestamp = _ensure_aware(record.get("timestamp"))
            if timestamp < start or timestamp > now:
                continue
            index = int((timestamp - start).total_seconds() // bucket_seconds)
            buckets[min(index, bucket_count - 1)]["count"] += 1
        return buckets

    async def verify_audit_chain(self) -> bool:
        """Re-verify checksums and linkage for the entire stored chain.

        Returns ``False`` on any tampered or broken link. The oldest
        remaining event is treated as genesis (its ``previous_checksum`` is
        not resolvable after pruning).
        """
        previous_checksum: Optional[str] = None
        for record in self._audit_chain:
            expected_previous = (
                previous_checksum if previous_checksum is not None else GENESIS_CHECKSUM
            )
            if record.get("previous_checksum") != expected_previous:
                logger.warning("Audit chain broken at event %s (linkage)", record.get("id"))
                return False
            expected = self._compute_audit_checksum(record, expected_previous)
            if record.get("checksum") != expected:
                logger.warning("Audit chain broken at event %s (checksum)", record.get("id"))
                return False
            previous_checksum = record["checksum"]
        return True


    # -- webhooks ----------------------------------------------------------------

    async def save_webhook_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Create a webhook endpoint record."""
        if not isinstance(endpoint, dict) or not endpoint.get("url"):
            raise ValueError("endpoint must be a dict with a url")
        record = copy.deepcopy(endpoint)
        record.setdefault("id", _new_id())
        record.setdefault("events", [])
        record.setdefault("enabled", True)
        record.setdefault("created_at", _utcnow())
        self._webhook_endpoints[record["id"]] = record
        return copy.deepcopy(record)

    async def get_webhook_endpoint(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        record = self._webhook_endpoints.get(endpoint_id)
        return copy.deepcopy(record) if record else None

    async def list_webhook_endpoints(self) -> List[Dict[str, Any]]:
        ordered = sorted(self._webhook_endpoints.values(), key=lambda r: r.get("created_at"))
        return [copy.deepcopy(r) for r in ordered]

    async def update_webhook_endpoint(
        self, endpoint_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        record = self._webhook_endpoints.get(endpoint_id)
        if record is None:
            return None
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        if "id" in updates:
            raise ValueError("id is immutable")
        record.update(copy.deepcopy(updates))
        record["updated_at"] = _utcnow()
        return copy.deepcopy(record)

    async def delete_webhook_endpoint(self, endpoint_id: str) -> bool:
        removed = self._webhook_endpoints.pop(endpoint_id, None) is not None
        if removed:
            self._webhook_deliveries = [
                delivery
                for delivery in self._webhook_deliveries
                if delivery.get("endpoint_id") != endpoint_id
            ]
        return removed

    async def save_webhook_delivery(self, delivery: Dict[str, Any]) -> Dict[str, Any]:
        """Record a delivery attempt for an endpoint."""
        if not isinstance(delivery, dict) or not delivery.get("endpoint_id"):
            raise ValueError("delivery must be a dict with an endpoint_id")
        if delivery["endpoint_id"] not in self._webhook_endpoints:
            raise IntegrityError(
                f"Webhook endpoint {delivery['endpoint_id']!r} does not exist"
            )
        record = copy.deepcopy(delivery)
        record.setdefault("id", _new_id())
        record.setdefault("created_at", _utcnow())
        self._webhook_deliveries.append(record)
        return copy.deepcopy(record)

    async def get_webhook_deliveries(
        self, endpoint_id: str, *, limit: int = 50
    ) -> List[Dict[str, Any]]:
        if limit < 0:
            raise ValueError("limit must be non-negative")
        matching = [
            delivery
            for delivery in self._webhook_deliveries
            if delivery.get("endpoint_id") == endpoint_id
        ]
        matching.sort(key=lambda r: r.get("created_at"), reverse=True)
        return [copy.deepcopy(r) for r in matching[:limit]]

    # -- RBAC -----------------------------------------------------------------------

    async def save_role(self, role: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update a role (unique name)."""
        if not isinstance(role, dict) or not role.get("name"):
            raise ValueError("role must be a dict with a name")
        role_id = role.get("id")
        existing = self._roles.get(role_id) if role_id else None
        for other in self._roles.values():
            if other["name"] == role["name"] and (existing is None or other["id"] != existing["id"]):
                raise IntegrityError(f"A role named {role['name']!r} already exists")
        record = copy.deepcopy(role)
        if existing is None:
            record.setdefault("id", _new_id())
            record.setdefault("created_at", _utcnow())
        else:
            record.setdefault("created_at", existing.get("created_at"))
        record.setdefault("permissions", [])
        record["updated_at"] = _utcnow()
        self._roles[record["id"]] = record
        return copy.deepcopy(record)

    async def get_role(self, role_id: str) -> Optional[Dict[str, Any]]:
        record = self._roles.get(role_id)
        return copy.deepcopy(record) if record else None

    async def list_roles(self) -> List[Dict[str, Any]]:
        ordered = sorted(self._roles.values(), key=lambda r: r.get("created_at"))
        return [copy.deepcopy(r) for r in ordered]

    async def delete_role(self, role_id: str) -> bool:
        if role_id not in self._roles:
            return False
        for assignment in self._role_assignments.values():
            if assignment.get("role_id") == role_id:
                raise IntegrityError(
                    f"Role {role_id!r} still has assignments; remove them first"
                )
        del self._roles[role_id]
        return True

    async def save_role_assignment(self, assignment: Dict[str, Any]) -> Dict[str, Any]:
        """Create a role assignment (role must exist)."""
        if not isinstance(assignment, dict):
            raise ValueError("assignment must be a dict")
        if not assignment.get("user_id") or not assignment.get("role_id"):
            raise ValueError("assignment requires user_id and role_id")
        if assignment["role_id"] not in self._roles:
            raise IntegrityError(f"Role {assignment['role_id']!r} does not exist")
        record = copy.deepcopy(assignment)
        record.setdefault("id", _new_id())
        record.setdefault("created_at", _utcnow())
        self._role_assignments[record["id"]] = record
        return copy.deepcopy(record)

    async def query_role_assignments(
        self,
        *,
        user_id: Optional[str] = None,
        role_id: Optional[str] = None,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for record in self._role_assignments.values():
            if user_id is not None and record.get("user_id") != user_id:
                continue
            if role_id is not None and record.get("role_id") != role_id:
                continue
            if scope_type is not None and record.get("scope_type") != scope_type:
                continue
            if scope_id is not None and record.get("scope_id") != scope_id:
                continue
            results.append(copy.deepcopy(record))
        results.sort(key=lambda r: r.get("created_at"))
        return results

    async def delete_role_assignment(self, assignment_id: str) -> bool:
        return self._role_assignments.pop(assignment_id, None) is not None

    # -- api keys ----------------------------------------------------------------------

    async def save_api_key(self, key_record: Dict[str, Any]) -> Dict[str, Any]:
        """Store an API key record; only the sha256 hash is persisted."""
        if not isinstance(key_record, dict):
            raise ValueError("key_record must be a dict")
        if key_record.get("key") or key_record.get("api_key"):
            raise ValueError(
                "plaintext API keys must never be stored; pass key_hash (sha256)"
            )
        key_hash = key_record.get("key_hash")
        if not key_hash or not isinstance(key_hash, str):
            raise ValueError("key_record.key_hash (sha256 hex) is required")
        existing_id = self._api_keys_by_hash.get(key_hash)
        if existing_id and existing_id != key_record.get("id"):
            raise IntegrityError("An API key with this hash already exists")
        record = copy.deepcopy(key_record)
        record.setdefault("id", _new_id())
        record.setdefault("revoked", False)
        record.setdefault("created_at", _utcnow())
        self._api_keys[record["id"]] = record
        self._api_keys_by_hash[key_hash] = record["id"]
        return copy.deepcopy(record)

    async def get_api_key_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        key_id = self._api_keys_by_hash.get(key_hash)
        if key_id is None:
            return None
        return copy.deepcopy(self._api_keys[key_id])

    async def list_api_keys(self) -> List[Dict[str, Any]]:
        ordered = sorted(self._api_keys.values(), key=lambda r: r.get("created_at"))
        return [copy.deepcopy(r) for r in ordered]

    async def revoke_api_key(self, key_id: str) -> bool:
        record = self._api_keys.get(key_id)
        if record is None:
            return False
        record["revoked"] = True
        record["revoked_at"] = _utcnow()
        return True

    # -- settings --------------------------------------------------------------------------

    async def get_setting(self, key: str) -> Any:
        value = self._settings.get(key)
        return copy.deepcopy(value)

    async def set_setting(self, key: str, value: Any) -> None:
        if not key or not isinstance(key, str):
            raise ValueError("setting key must be a non-empty string")
        try:
            json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"setting value for {key!r} must be JSON-serializable") from exc
        self._settings[key] = copy.deepcopy(value)

    # -- SAML ---------------------------------------------------------------------------------

    def _saml_request_expired(self, request_id: str) -> bool:
        entry = self._saml_requests.get(request_id)
        if entry is None:
            return True
        _, expires = entry
        if expires <= _utcnow().timestamp():
            del self._saml_requests[request_id]
            return True
        return False

    async def save_saml_request(
        self, request_id: str, data: Dict[str, Any], *, ttl_seconds: int
    ) -> None:
        """Store transient SAML request state with a TTL."""
        if not request_id or not isinstance(request_id, str):
            raise ValueError("request_id must be a non-empty string")
        if not isinstance(data, dict):
            raise ValueError("data must be a dict")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        async with self._lock:
            self._saml_requests[request_id] = (
                copy.deepcopy(data),
                _utcnow().timestamp() + ttl_seconds,
            )

    async def consume_saml_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Atomic fetch-and-delete; exactly one consumer wins."""
        async with self._lock:
            if self._saml_request_expired(request_id):
                return None
            data, _ = self._saml_requests.pop(request_id)
            return copy.deepcopy(data)

    def _saml_response_expired(self, response_id: str) -> bool:
        if response_id not in self._saml_response_ids:
            return True
        expires = self._saml_response_ids[response_id]
        # expires is None for persistent records (no TTL).
        if expires is not None and expires <= _utcnow().timestamp():
            del self._saml_response_ids[response_id]
            return True
        return False

    async def save_saml_response_id(self, response_id: str, *, ttl_seconds: int) -> None:
        """Record a consumed ResponseID for replay protection."""
        if not response_id or not isinstance(response_id, str):
            raise ValueError("response_id must be a non-empty string")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        async with self._lock:
            self._saml_response_ids[response_id] = _utcnow().timestamp() + ttl_seconds

    async def check_and_record_saml_response_id(self, response_id: str) -> bool:
        """Return ``True`` when fresh (and record it); ``False`` on replay."""
        if not response_id or not isinstance(response_id, str):
            raise ValueError("response_id must be a non-empty string")
        async with self._lock:
            if not self._saml_response_expired(response_id):
                return False
            # No TTL parameter in the contract: keep the ledger entry forever.
            self._saml_response_ids[response_id] = None
            return True

    async def save_saml_user_mapping(
        self, name_id: str, sp_entity_id: str, user_id: str
    ) -> None:
        if not name_id or not sp_entity_id or not user_id:
            raise ValueError("name_id, sp_entity_id and user_id are required")
        self._saml_user_mappings[(name_id, sp_entity_id)] = user_id

    async def get_saml_user_mapping(
        self, name_id: str, sp_entity_id: str
    ) -> Optional[str]:
        return self._saml_user_mappings.get((name_id, sp_entity_id))

    # -- OIDC ------------------------------------------------------------------------------------

    async def save_oidc_provider(self, provider: Dict[str, Any]) -> Dict[str, Any]:
        """Create an OIDC provider with unique issuer and slug."""
        if not isinstance(provider, dict):
            raise ValueError("provider must be a dict")
        if not provider.get("issuer") or not provider.get("name"):
            raise ValueError("provider requires issuer and name")
        record = copy.deepcopy(provider)
        record.setdefault("id", _new_id())
        record.setdefault("slug", _slugify(str(record["name"])))
        record.setdefault("enabled", True)
        record.setdefault("created_at", _utcnow())
        issuer = str(record["issuer"])
        slug = str(record["slug"]).lower()
        if issuer in self._oidc_by_issuer:
            raise IntegrityError(f"An OIDC provider with issuer {issuer!r} already exists")
        if slug in self._oidc_by_slug:
            raise IntegrityError(f"An OIDC provider with slug {slug!r} already exists")
        record["slug"] = slug
        self._oidc_providers[record["id"]] = record
        self._oidc_by_issuer[issuer] = record["id"]
        self._oidc_by_slug[slug] = record["id"]
        return copy.deepcopy(record)

    async def get_oidc_provider(self, issuer_or_slug: str) -> Optional[Dict[str, Any]]:
        provider_id = self._oidc_by_issuer.get(issuer_or_slug) or self._oidc_by_slug.get(
            str(issuer_or_slug).lower()
        )
        if provider_id is None:
            return None
        return copy.deepcopy(self._oidc_providers[provider_id])

    async def update_oidc_provider(
        self, identifier: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Whitelisted update; unknown keys raise ``ValueError``."""
        provider_id = self._oidc_by_issuer.get(identifier) or self._oidc_by_slug.get(
            str(identifier).lower()
        )
        if provider_id is None:
            return None
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        rejected = set(updates) - OIDC_UPDATABLE_FIELDS
        if rejected:
            raise ValueError(
                f"OIDC provider fields not updatable: {sorted(rejected)}"
            )
        record = self._oidc_providers[provider_id]

        new_issuer = updates.get("issuer")
        if new_issuer is not None and str(new_issuer) != record["issuer"]:
            if str(new_issuer) in self._oidc_by_issuer:
                raise IntegrityError(
                    f"An OIDC provider with issuer {new_issuer!r} already exists"
                )
            del self._oidc_by_issuer[record["issuer"]]
            record["issuer"] = str(new_issuer)
            self._oidc_by_issuer[record["issuer"]] = provider_id

        new_slug = updates.get("slug")
        if new_slug is not None and str(new_slug).lower() != record["slug"]:
            candidate = str(new_slug).lower()
            if candidate in self._oidc_by_slug:
                raise IntegrityError(
                    f"An OIDC provider with slug {candidate!r} already exists"
                )
            del self._oidc_by_slug[record["slug"]]
            record["slug"] = candidate
            self._oidc_by_slug[candidate] = provider_id

        for key, value in updates.items():
            if key not in ("issuer", "slug"):
                record[key] = copy.deepcopy(value)
        record["updated_at"] = _utcnow()
        return copy.deepcopy(record)
