"""Organization & multi-tenancy management (CONTRACTS.md §4/§5).

Implements organizations, memberships, and invitations strictly on top of
the unified database contract (``create_organization``, ``add_org_member``,
``create_invitation``, ``get_invitation_by_token``, ...).

Key semantics:

- ``OrganizationManager(db, ...)`` — the db contract is required; the email
  service is OPTIONAL. When ``email_service`` is ``None`` invitations are
  still created and returned with their accept token — sending is skipped
  and logged (§5).
- Slugs get a uniqueness fallback (``acme`` -> ``acme-<hex>``).
- Member counts are capped per plan (:data:`PLAN_MAX_MEMBERS`).
- The last owner can neither be removed nor demoted.
- Invitations expire (``expires_at``) and are single-use: accepting
  consumes them via ``get_invitation_by_token`` + ``delete_invitation``.
- Invitation sends are rate-limited via cache counters (§3.1 key schema).
- Tokens come from ``secrets.token_urlsafe`` (§0.3); ids from
  ``secrets.token_hex``.
"""

from __future__ import annotations

import inspect
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from authy_package.db.abstract_db import AbstractDatabase
from authy_package.cache.abstract_cache import AbstractCache
from authy_package.errors import IntegrityError, NotFoundError

logger = logging.getLogger("authy.organizations")

__all__ = [
    "OrgRole",
    "InvitationStatus",
    "PLAN_MAX_MEMBERS",
    "VALID_PLANS",
    "OrganizationManager",
]

#: Cache key for invitation-send rate limiting (§3.1 schema).
INVITE_RATE_LIMIT_KEY_TEMPLATE = "authy:ratelimit:orginvite:{org_id}"


class OrgRole(Enum):
    """Organization membership roles."""

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    GUEST = "guest"


class InvitationStatus(Enum):
    """Invitation lifecycle states."""

    PENDING = "pending"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    EXPIRED = "expired"


#: Member caps enforced per plan.
PLAN_MAX_MEMBERS: Dict[str, int] = {
    "free": 10,
    "pro": 50,
    "enterprise": 1000,
}

#: Plans accepted by :meth:`OrganizationManager.create_organization`.
VALID_PLANS = tuple(PLAN_MAX_MEMBERS)


def _utcnow() -> datetime:
    """Timezone-aware UTC now (§0.5)."""
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime) -> datetime:
    """Attach UTC to naive datetimes so comparisons never raise."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _slugify(name: str) -> str:
    """Derive a URL-safe slug from an organization name."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "org"


class OrganizationManager:
    """Multi-tenant organizations on top of the §4 db contract.

    Args:
        db: Required database implementing the unified contract.
        cache: Optional cache; enables invitation-send rate limiting.
        email_service: Optional; when ``None`` invitation emails are
            skipped (logged) but invitations are still created with tokens.
        invitation_ttl_seconds: Default invitation lifetime (72h).
        max_invitations_per_window: Rate-limit threshold per org.
        invitation_rate_window_seconds: Rate-limit window (1h).
    """

    def __init__(
        self,
        db: AbstractDatabase,
        *,
        cache: Optional[AbstractCache] = None,
        email_service: Optional[Any] = None,
        invitation_ttl_seconds: int = 72 * 3600,
        max_invitations_per_window: int = 10,
        invitation_rate_window_seconds: int = 3600,
    ) -> None:
        if invitation_ttl_seconds <= 0:
            raise ValueError("invitation_ttl_seconds must be positive")
        self.db = db
        self.cache = cache
        self.email_service = email_service
        self._invitation_ttl = invitation_ttl_seconds
        self._max_invites_per_window = max_invitations_per_window
        self._invite_window_seconds = invitation_rate_window_seconds

    # -- organizations --------------------------------------------------------

    async def create_organization(
        self,
        name: str,
        owner_id: str,
        *,
        description: Optional[str] = None,
        plan: str = "free",
        slug: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create an organization and add the owner as its first member.

        Raises:
            ValueError: On empty inputs or an unknown plan.
        """
        if not name or not str(name).strip():
            raise ValueError("name must be a non-empty string")
        if not owner_id or not str(owner_id).strip():
            raise ValueError("owner_id must be a non-empty string")
        if plan not in PLAN_MAX_MEMBERS:
            raise ValueError(
                f"plan must be one of {VALID_PLANS}, got {plan!r}"
            )

        base_slug = _slugify(slug or name)
        candidate_slug = base_slug
        # Slug uniqueness fallback: append a random suffix on collision.
        if await self.db.get_organization_by_slug(candidate_slug) is not None:
            candidate_slug = f"{base_slug}-{secrets.token_hex(3)}"

        org = await self.db.create_organization(
            {
                "name": str(name).strip(),
                "slug": candidate_slug,
                "description": description,
                "plan": plan,
                "max_members": PLAN_MAX_MEMBERS[plan],
                "owner_id": owner_id,
                "metadata": dict(metadata or {}),
                "is_active": True,
            }
        )
        await self.db.add_org_member(
            org["id"],
            {"user_id": owner_id, "role": OrgRole.OWNER.value, "added_by": None},
        )
        logger.info("Created organization %s (%s)", org["id"], org["slug"])
        return org

    async def get_organization(self, org_id: str) -> Optional[Dict[str, Any]]:
        """Fetch an organization by id."""
        return await self.db.get_organization(org_id)

    async def get_organization_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        """Fetch an organization by slug."""
        return await self.db.get_organization_by_slug(slug)

    async def update_organization(
        self, org_id: str, updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update organization fields (name/description/plan/metadata...)."""
        org = await self.db.update_organization(org_id, updates)
        if org is None:
            raise NotFoundError(f"Organization {org_id!r} does not exist")
        return org

    async def delete_organization(self, org_id: str) -> bool:
        """Delete an organization and its member/invitation links."""
        return await self.db.delete_organization(org_id)

    async def get_organizations_paginated(
        self, *, page: int = 1, page_size: int = 20, search: Optional[str] = None
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Paginated organization listing with optional name/slug search."""
        if page < 1 or page_size < 1:
            raise ValueError("page and page_size must be >= 1")
        rows, _total = await self.db.list_organizations(limit=10000, offset=0)
        if search:
            needle = search.lower()
            rows = [
                org
                for org in rows
                if needle in str(org.get("name", "")).lower()
                or needle in str(org.get("slug", "")).lower()
            ]
        total = len(rows)
        start = (page - 1) * page_size
        return rows[start : start + page_size], total

    async def get_user_organizations(self, user_id: str) -> List[Dict[str, Any]]:
        """All active organizations a user belongs to."""
        rows, _total = await self.db.list_organizations(limit=10000, offset=0)
        orgs: List[Dict[str, Any]] = []
        for org in rows:
            members = await self.db.get_org_members(org["id"])
            if any(member.get("user_id") == user_id for member in members):
                orgs.append(org)
        return orgs

    # -- members ------------------------------------------------------------------

    async def add_member(
        self,
        org_id: str,
        user_id: str,
        role: "OrgRole | str" = OrgRole.MEMBER,
        *,
        added_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add a member, enforcing the plan member cap.

        Raises:
            NotFoundError: When the organization does not exist.
            ValueError: When the member limit is reached.
            IntegrityError: When the user is already a member.
        """
        org = await self.db.get_organization(org_id)
        if org is None:
            raise NotFoundError(f"Organization {org_id!r} does not exist")
        if not user_id or not str(user_id).strip():
            raise ValueError("user_id must be a non-empty string")

        max_members = org.get("max_members", PLAN_MAX_MEMBERS[org.get("plan", "free")])
        members = await self.db.get_org_members(org_id)
        if len(members) >= max_members:
            raise ValueError(
                f"Organization member limit reached ({max_members} for plan "
                f"{org.get('plan')!r})"
            )

        org_role = role.value if isinstance(role, OrgRole) else OrgRole(str(role)).value
        return await self.db.add_org_member(
            org_id,
            {"user_id": user_id, "role": org_role, "added_by": added_by},
        )

    async def remove_member(self, org_id: str, user_id: str) -> bool:
        """Remove a member; refuses to remove the last owner."""
        members = await self.db.get_org_members(org_id)
        member = next((m for m in members if m.get("user_id") == user_id), None)
        if member is None:
            return False
        if member.get("role") == OrgRole.OWNER.value:
            owners = [m for m in members if m.get("role") == OrgRole.OWNER.value]
            if len(owners) <= 1:
                raise PermissionError("Cannot remove the last owner of an organization")
        return await self.db.remove_org_member(org_id, user_id)

    async def update_member_role(
        self, org_id: str, user_id: str, new_role: "OrgRole | str"
    ) -> Dict[str, Any]:
        """Change a member's role; refuses to demote the last owner."""
        org_role = (
            new_role.value if isinstance(new_role, OrgRole) else OrgRole(str(new_role)).value
        )
        members = await self.db.get_org_members(org_id)
        member = next((m for m in members if m.get("user_id") == user_id), None)
        if member is None:
            raise NotFoundError(f"User {user_id!r} is not a member of {org_id!r}")
        if (
            member.get("role") == OrgRole.OWNER.value
            and org_role != OrgRole.OWNER.value
        ):
            owners = [m for m in members if m.get("role") == OrgRole.OWNER.value]
            if len(owners) <= 1:
                raise PermissionError("Cannot demote the last owner of an organization")
        updated = await self.db.update_org_member(org_id, user_id, {"role": org_role})
        if updated is None:
            raise NotFoundError(f"Member record for {user_id!r} not found")
        return updated

    async def get_members(self, org_id: str) -> List[Dict[str, Any]]:
        """List the members of an organization."""
        return await self.db.get_org_members(org_id)

    async def get_member_role(self, org_id: str, user_id: str) -> Optional[OrgRole]:
        """Return the member's role, or ``None`` when not a member."""
        members = await self.db.get_org_members(org_id)
        for member in members:
            if member.get("user_id") == user_id:
                return OrgRole(member.get("role", "member"))
        return None

    # -- invitations -----------------------------------------------------------------

    async def _enforce_invitation_rate_limit(self, org_id: str) -> None:
        """Rate-limit invitation sends per organization via cache counters."""
        if self.cache is None:
            return
        key = INVITE_RATE_LIMIT_KEY_TEMPLATE.format(org_id=org_id)
        count = await self.cache.incr(key)
        if count == 1:
            await self.cache.expire(key, self._invite_window_seconds)
        if count > self._max_invites_per_window:
            from authy_package.errors import RateLimitError

            raise RateLimitError(
                "Too many invitations sent for this organization; try again later",
                retry_after=self._invite_window_seconds,
                code="invitation_rate_limited",
            )

    async def send_invitation(
        self,
        org_id: str,
        email: str,
        role: "OrgRole | str" = OrgRole.MEMBER,
        *,
        invited_by: str,
        expires_in_hours: Optional[int] = None,
        message: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create an invitation (and email it when a service is configured).

        The invitation is ALWAYS created and returned with its accept token;
        when ``email_service`` is ``None`` the email send is skipped and
        logged. Tokens are single-use and expire.

        Raises:
            NotFoundError: When the organization does not exist.
            ValueError: On a malformed email.
            IntegrityError: When a pending invitation for the email exists.
            RateLimitError: When the org's invitation rate limit is hit.
        """
        org = await self.db.get_organization(org_id)
        if org is None:
            raise NotFoundError(f"Organization {org_id!r} does not exist")
        if not email or "@" not in email:
            raise ValueError("email must be a valid email address")

        pending = await self.db.get_pending_invitations(org_id)
        normalized_email = email.strip().lower()
        if any(
            str(inv.get("email", "")).lower() == normalized_email for inv in pending
        ):
            raise IntegrityError(
                f"A pending invitation for {email!r} already exists"
            )

        await self._enforce_invitation_rate_limit(org_id)

        org_role = role.value if isinstance(role, OrgRole) else OrgRole(str(role)).value
        ttl = (
            expires_in_hours * 3600
            if expires_in_hours and expires_in_hours > 0
            else self._invitation_ttl
        )
        now = _utcnow()
        invitation = await self.db.create_invitation(
            {
                "org_id": org_id,
                "email": email.strip(),
                "role": org_role,
                "status": InvitationStatus.PENDING.value,
                "invited_by": invited_by,
                "message": message,
                "token": secrets.token_urlsafe(32),
                "created_at": now,
                "expires_at": now + timedelta(seconds=ttl),
            }
        )

        if self.email_service is None:
            logger.info(
                "Email service not configured; invitation %s for %s created "
                "without sending email (token available to the caller)",
                invitation["id"],
                normalized_email,
            )
        else:
            invite_link = f"/auth/invite?token={invitation['token']}"
            result = self.email_service.send_invitation_email(
                to=invitation["email"],
                org_name=org.get("name"),
                invite_link=invite_link,
                role=org_role,
            )
            if inspect.isawaitable(result):
                await result
            logger.info("Invitation %s emailed to %s", invitation["id"], normalized_email)

        return invitation

    async def get_pending_invitations(self, org_id: str) -> List[Dict[str, Any]]:
        """Pending (unexpired) invitations; expired ones are purged."""
        pending = await self.db.get_pending_invitations(org_id)
        now = _utcnow()
        active: List[Dict[str, Any]] = []
        for invitation in pending:
            expires_at = invitation.get("expires_at")
            if expires_at is not None and _ensure_aware(expires_at) <= now:
                await self.db.delete_invitation(invitation["id"])
                logger.info("Invitation %s expired and was removed", invitation["id"])
                continue
            active.append(invitation)
        return active

    async def accept_invitation(self, token: str, user_id: str) -> Dict[str, Any]:
        """Accept an invitation: single-use, expiry-checked, adds membership.

        Raises:
            ValueError: On a missing token.
            NotFoundError: When the invitation is unknown, expired, or the
                accepting user's email does not match.
            PermissionError: When the organization is at its member cap.
        """
        if not token or not isinstance(token, str):
            raise ValueError("token must be a non-empty string")
        invitation = await self.db.get_invitation_by_token(token)
        if invitation is None:
            raise NotFoundError("Invitation not found or already used")
        if invitation.get("status") != InvitationStatus.PENDING.value:
            raise NotFoundError("Invitation is no longer valid")

        expires_at = invitation.get("expires_at")
        if expires_at is not None and _ensure_aware(expires_at) <= _utcnow():
            await self.db.delete_invitation(invitation["id"])
            raise NotFoundError("Invitation has expired")

        user = await self.db.get_user_by_id(user_id)
        if user is None:
            raise NotFoundError(f"User {user_id!r} does not exist")
        invited_email = str(invitation.get("email", "")).lower()
        user_email = str(user.get("email", "")).lower()
        if invited_email and user_email and invited_email != user_email:
            raise NotFoundError("This invitation was issued for a different email address")

        # Consume BEFORE adding the member so a failed add cannot leave a
        # replayable invitation behind; single-use is atomic enough here
        # because get_invitation_by_token + delete runs in one coroutine.
        await self.db.delete_invitation(invitation["id"])

        org = await self.db.get_organization(invitation["org_id"])
        if org is None:
            raise NotFoundError("The organization for this invitation no longer exists")
        max_members = org.get("max_members", PLAN_MAX_MEMBERS[org.get("plan", "free")])
        members = await self.db.get_org_members(org["id"])
        if len(members) >= max_members:
            raise PermissionError("Organization member limit reached")

        member = await self.db.add_org_member(
            org["id"],
            {
                "user_id": user_id,
                "role": invitation.get("role", OrgRole.MEMBER.value),
                "added_by": invitation.get("invited_by"),
                "invitation_id": invitation["id"],
            },
        )
        logger.info("Invitation %s accepted by user %s", invitation["id"], user_id)
        return member

    async def decline_invitation(self, token: str) -> bool:
        """Decline (delete) a pending invitation by token."""
        invitation = await self.db.get_invitation_by_token(token)
        if invitation is None:
            return False
        return await self.db.delete_invitation(invitation["id"])
