"""Role-based access control engine (CONTRACTS.md §4 RBAC + §8).

Roles and assignments are persisted through the unified db contract
(``save_role`` / ``list_roles`` / ``save_role_assignment`` /
``query_role_assignments`` / ``delete_role_assignment``). The manager keeps
an in-memory role cache that is loaded from the db at initialization
(:meth:`RBACManager.create`) and refreshed after every write.

Semantics:

- Four scope levels: ``global``, ``organization``, ``team``, ``resource``.
  A ``global`` assignment applies to every scope.
- Role inheritance via ``inherits_from`` (role id) with a strict cycle
  guard on create/update and a visited-set during evaluation.
- Permissions are string names (``"audit:read"``); a granted permission
  ending in ``"*"`` matches as a prefix wildcard (``"admin:*"``).
- Assignments may carry ``expires_at``; expiry is checked at evaluation
  time.
- System roles (``owner``/``admin``/``superadmin`` or ``is_system=True``)
  cannot be modified or deleted.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from authy_package.db.abstract_db import AbstractDatabase
from authy_package.errors import NotFoundError

logger = logging.getLogger("authy.admin.rbac")

__all__ = ["PermissionScope", "RBACManager", "SYSTEM_ROLE_NAMES"]

#: Role names that are always treated as protected system roles.
SYSTEM_ROLE_NAMES = frozenset({"owner", "admin", "superadmin"})


class PermissionScope(str, Enum):
    """The four RBAC scope levels."""

    GLOBAL = "global"
    ORGANIZATION = "organization"
    TEAM = "team"
    RESOURCE = "resource"


def _utcnow() -> datetime:
    """Timezone-aware UTC now (§0.5)."""
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime) -> datetime:
    """Attach UTC to naive datetimes so comparisons never raise."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _coerce_scope(scope: "PermissionScope | str") -> PermissionScope:
    if isinstance(scope, PermissionScope):
        return scope
    return PermissionScope(scope)


def _parse_expiry(value: Any) -> Optional[datetime]:
    """Parse stored expires_at values (datetime or ISO string)."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return _ensure_aware(value)
    if isinstance(value, str):
        try:
            return _ensure_aware(datetime.fromisoformat(value))
        except ValueError:
            logger.warning("Unparsable expires_at value: %r", value)
            return None
    return None


def permission_matches(granted: str, requested: str) -> bool:
    """True when a granted permission covers the requested one.

    Exact match always works; a grant ending in ``*`` is a prefix wildcard
    (``"admin:*"`` covers ``"admin:users"``).
    """
    if not granted or not requested:
        return False
    if granted == requested:
        return True
    if granted.endswith("*"):
        return requested.startswith(granted[:-1])
    return False


class RBACManager:
    """RBAC engine persisted via the §4 db contract.

    Construct via :meth:`RBACManager.create` so the role cache is loaded
    from the database before first use::

        rbac = await RBACManager.create(db)
    """

    def __init__(self, db: AbstractDatabase) -> None:
        self.db = db
        self._roles_by_id: Dict[str, Dict[str, Any]] = {}
        self._loaded = False

    # -- cache lifecycle ------------------------------------------------------

    @classmethod
    async def create(cls, db: AbstractDatabase) -> "RBACManager":
        """Construct a manager and load the role cache from the db."""
        manager = cls(db)
        await manager.load()
        return manager

    async def load(self) -> None:
        """(Re)load the role cache from the database."""
        roles = await self.db.list_roles()
        self._roles_by_id = {role["id"]: role for role in roles}
        self._loaded = True

    async def _ensure_loaded(self) -> None:
        if not self._loaded:
            await self.load()

    def _is_system_role(self, role: Dict[str, Any]) -> bool:
        return bool(role.get("is_system")) or str(role.get("name", "")).lower() in SYSTEM_ROLE_NAMES

    # -- role management ---------------------------------------------------------

    async def create_role(
        self,
        name: str,
        description: str = "",
        permissions: Optional[List[str]] = None,
        *,
        inherits_from: Optional[str] = None,
        organization_id: Optional[str] = None,
        is_system: bool = False,
    ) -> Dict[str, Any]:
        """Create a role and refresh the cache.

        Raises:
            ValueError: On empty name or unknown/cyclic inheritance.
            IntegrityError: On duplicate role names (from the db).
        """
        if not name or not str(name).strip():
            raise ValueError("Role name must be a non-empty string")
        await self._ensure_loaded()
        if inherits_from is not None:
            if inherits_from not in self._roles_by_id:
                raise ValueError(f"Parent role {inherits_from!r} does not exist")
        role = await self.db.save_role(
            {
                "name": str(name).strip(),
                "description": description,
                "permissions": list(permissions or []),
                "inherits_from": inherits_from,
                "organization_id": organization_id,
                "is_system": bool(is_system),
            }
        )
        self._roles_by_id[role["id"]] = role
        return role

    async def update_role(
        self,
        role_id: str,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        inherits_from: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update a non-system role; re-checks the inheritance cycle guard."""
        await self._ensure_loaded()
        role = self._roles_by_id.get(role_id)
        if role is None:
            raise NotFoundError(f"Role {role_id!r} does not exist")
        if self._is_system_role(role):
            raise PermissionError("System roles cannot be modified")

        updates: Dict[str, Any] = {"id": role_id}
        if name is not None:
            if not str(name).strip():
                raise ValueError("Role name must be a non-empty string")
            updates["name"] = str(name).strip()
        if description is not None:
            updates["description"] = description
        if permissions is not None:
            updates["permissions"] = list(permissions)
        if inherits_from is not None:
            if inherits_from not in self._roles_by_id:
                raise ValueError(f"Parent role {inherits_from!r} does not exist")
            self._check_cycle(role_id, inherits_from)
            updates["inherits_from"] = inherits_from

        # save_role needs the full record for the in-memory adapter's
        # created_at preservation; merge current state with updates.
        merged = {key: value for key, value in role.items() if key != "updated_at"}
        merged.update(updates)
        updated = await self.db.save_role(merged)
        self._roles_by_id[updated["id"]] = updated
        return updated

    async def delete_role(self, role_id: str) -> bool:
        """Delete a non-system role (db refuses when assignments remain)."""
        await self._ensure_loaded()
        role = self._roles_by_id.get(role_id)
        if role is None:
            return False
        if self._is_system_role(role):
            raise PermissionError("System roles cannot be deleted")
        removed = await self.db.delete_role(role_id)
        if removed:
            self._roles_by_id.pop(role_id, None)
        return removed

    async def list_roles(
        self, *, organization_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List roles; with ``organization_id`` returns global + that org's."""
        await self._ensure_loaded()
        roles = list(self._roles_by_id.values())
        if organization_id is not None:
            roles = [
                role
                for role in roles
                if role.get("organization_id") in (None, organization_id)
            ]
        return roles

    async def get_role(self, role_id: str) -> Optional[Dict[str, Any]]:
        """Fetch one role by id."""
        await self._ensure_loaded()
        return self._roles_by_id.get(role_id)

    def _check_cycle(self, role_id: str, parent_id: str) -> None:
        """Raise ValueError when setting ``role_id``'s parent creates a cycle."""
        visited = {role_id}
        current = parent_id
        while current is not None:
            if current in visited:
                raise ValueError(
                    f"Role inheritance cycle detected involving {current!r}"
                )
            visited.add(current)
            parent = self._roles_by_id.get(current)
            current = parent.get("inherits_from") if parent else None

    # -- assignment management ---------------------------------------------------

    async def assign_role(
        self,
        user_id: str,
        role_id: str,
        *,
        scope_type: "PermissionScope | str" = PermissionScope.GLOBAL,
        scope_id: Optional[str] = None,
        granted_by: str,
        expires_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Assign a role to a user in a scope.

        ``granted_by`` MUST be the authenticated principal performing the
        grant (no placeholders). Time-limited assignments pass
        ``expires_at`` and stop evaluating once expired.
        """
        if not user_id or not str(user_id).strip():
            raise ValueError("user_id must be a non-empty string")
        if not granted_by or not str(granted_by).strip():
            raise ValueError("granted_by must identify the granting principal")
        await self._ensure_loaded()
        if role_id not in self._roles_by_id:
            raise NotFoundError(f"Role {role_id!r} does not exist")
        scope = _coerce_scope(scope_type)
        if scope != PermissionScope.GLOBAL and not scope_id:
            raise ValueError(f"scope_id is required for scope {scope.value!r}")

        assignment = await self.db.save_role_assignment(
            {
                "user_id": user_id,
                "role_id": role_id,
                "scope_type": scope.value,
                "scope_id": scope_id,
                "granted_by": granted_by,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "created_at": _utcnow(),
            }
        )
        logger.info(
            "Assigned role %s to user %s (scope %s/%s) by %s",
            role_id,
            user_id,
            scope.value,
            scope_id,
            granted_by,
        )
        return assignment

    async def revoke_assignment(self, assignment_id: str) -> bool:
        """Delete a role assignment."""
        return await self.db.delete_role_assignment(assignment_id)

    async def get_user_assignments(
        self,
        user_id: str,
        *,
        scope_type: Optional["PermissionScope | str"] = None,
        scope_id: Optional[str] = None,
        include_expired: bool = False,
    ) -> List[Dict[str, Any]]:
        """A user's assignments, expired ones filtered out by default."""
        kwargs: Dict[str, Any] = {"user_id": user_id}
        if scope_type is not None:
            kwargs["scope_type"] = _coerce_scope(scope_type).value
        if scope_id is not None:
            kwargs["scope_id"] = scope_id
        assignments = await self.db.query_role_assignments(**kwargs)
        if include_expired:
            return assignments
        now = _utcnow()
        active = []
        for assignment in assignments:
            expires_at = _parse_expiry(assignment.get("expires_at"))
            if expires_at is not None and expires_at <= now:
                continue
            active.append(assignment)
        return active

    # -- evaluation ------------------------------------------------------------------

    def _assignment_matches(
        self,
        assignment: Dict[str, Any],
        scope_type: PermissionScope,
        scope_id: Optional[str],
    ) -> bool:
        """Global grants apply everywhere; otherwise scope must match."""
        if assignment.get("scope_type") == PermissionScope.GLOBAL.value:
            return True
        if assignment.get("scope_type") != scope_type.value:
            return False
        return assignment.get("scope_id") == scope_id

    async def get_user_roles(
        self,
        user_id: str,
        scope_type: "PermissionScope | str" = PermissionScope.GLOBAL,
        scope_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Effective (non-expired, scope-matching) roles for a user."""
        await self._ensure_loaded()
        scope = _coerce_scope(scope_type)
        assignments = await self.get_user_assignments(user_id)
        roles: List[Dict[str, Any]] = []
        seen: set = set()
        for assignment in assignments:
            if not self._assignment_matches(assignment, scope, scope_id):
                continue
            role = self._roles_by_id.get(assignment.get("role_id"))
            if role is not None and role["id"] not in seen:
                seen.add(role["id"])
                roles.append(role)
        return roles

    async def get_effective_permissions(
        self,
        user_id: str,
        scope_type: "PermissionScope | str" = PermissionScope.GLOBAL,
        scope_id: Optional[str] = None,
    ) -> List[str]:
        """All permission names a user holds, incl. inherited ones."""
        roles = await self.get_user_roles(user_id, scope_type, scope_id)
        permissions: set = set()
        for role in roles:
            permissions.update(self._resolve_role_permissions(role))
        return sorted(permissions)

    def _resolve_role_permissions(self, role: Dict[str, Any]) -> set:
        """Permissions of a role incl. ancestors; cycle-safe via visited set."""
        collected: set = set()
        visited: set = set()
        stack = [role]
        while stack:
            current = stack.pop()
            if current["id"] in visited:
                continue
            visited.add(current["id"])
            collected.update(current.get("permissions") or [])
            parent_id = current.get("inherits_from")
            if parent_id and parent_id in self._roles_by_id:
                stack.append(self._roles_by_id[parent_id])
        return collected

    async def has_permission(
        self,
        user_id: str,
        permission: str,
        scope_type: "PermissionScope | str" = PermissionScope.GLOBAL,
        scope_id: Optional[str] = None,
    ) -> bool:
        """Check one permission with inheritance + wildcard + expiry."""
        effective = await self.get_effective_permissions(user_id, scope_type, scope_id)
        return any(permission_matches(granted, permission) for granted in effective)
