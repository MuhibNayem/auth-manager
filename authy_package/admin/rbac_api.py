"""RBAC administration API (CONTRACTS.md §8).

Every route is authenticated via the /admin/v2 principal dependency
(admin JWT or hashed API key). ``granted_by`` on assignments is ALWAYS
derived from the authenticated principal — never a placeholder.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from authy_package.admin.deps import (
    AdminDependencies,
    get_admin_deps,
    get_v2_principal,
)
from authy_package.admin.rbac_manager import PermissionScope, RBACManager
from authy_package.errors import NotFoundError

logger = logging.getLogger("authy.admin.rbac_api")

__all__ = ["rbac_router"]

rbac_router = APIRouter(
    prefix="/admin/v2/rbac",
    tags=["RBAC"],
    dependencies=[Depends(get_v2_principal)],
)


# ---------------------------------------------------------------------------
# schemas
# ---------------------------------------------------------------------------

class RoleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = ""
    permissions: List[str] = Field(default_factory=list)
    inherits_from: Optional[str] = None
    organization_id: Optional[str] = None


class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = None
    inherits_from: Optional[str] = None


class RoleAssignmentCreate(BaseModel):
    user_id: str = Field(..., min_length=1)
    role_id: str = Field(..., min_length=1)
    scope_type: PermissionScope = PermissionScope.GLOBAL
    scope_id: Optional[str] = None
    expires_at: Optional[datetime] = None


class PermissionCheckRequest(BaseModel):
    user_id: str = Field(..., min_length=1)
    permission: str = Field(..., min_length=1)
    scope_type: PermissionScope = PermissionScope.GLOBAL
    scope_id: Optional[str] = None


# ---------------------------------------------------------------------------
# dependency
# ---------------------------------------------------------------------------

def get_rbac_manager(
    deps: AdminDependencies = Depends(get_admin_deps),
) -> RBACManager:
    """Resolve the RBAC manager (503 when not configured)."""
    if deps.rbac is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="RBAC manager not configured",
        )
    return deps.rbac


# ---------------------------------------------------------------------------
# roles
# ---------------------------------------------------------------------------

@rbac_router.post("/roles", status_code=status.HTTP_201_CREATED)
async def create_role(
    body: RoleCreate,
    rbac: RBACManager = Depends(get_rbac_manager),
) -> Dict[str, Any]:
    """Create a custom role."""
    return await rbac.create_role(
        body.name,
        body.description,
        body.permissions,
        inherits_from=body.inherits_from,
        organization_id=body.organization_id,
    )


@rbac_router.get("/roles")
async def list_roles(
    organization_id: Optional[str] = None,
    rbac: RBACManager = Depends(get_rbac_manager),
) -> Dict[str, Any]:
    """List roles (optionally filtered to global + one organization)."""
    roles = await rbac.list_roles(organization_id=organization_id)
    return {"roles": roles, "total": len(roles)}


@rbac_router.get("/roles/{role_id}")
async def get_role(
    role_id: str,
    rbac: RBACManager = Depends(get_rbac_manager),
) -> Dict[str, Any]:
    """Fetch one role."""
    role = await rbac.get_role(role_id)
    if role is None:
        raise NotFoundError(f"Role {role_id!r} does not exist")
    return role


@rbac_router.put("/roles/{role_id}")
async def update_role(
    role_id: str,
    body: RoleUpdate,
    rbac: RBACManager = Depends(get_rbac_manager),
) -> Dict[str, Any]:
    """Update a custom role (system roles are rejected)."""
    return await rbac.update_role(
        role_id,
        name=body.name,
        description=body.description,
        permissions=body.permissions,
        inherits_from=body.inherits_from,
    )


@rbac_router.delete("/roles/{role_id}")
async def delete_role(
    role_id: str,
    rbac: RBACManager = Depends(get_rbac_manager),
) -> Dict[str, Any]:
    """Delete a custom role with no remaining assignments."""
    if not await rbac.delete_role(role_id):
        raise NotFoundError(f"Role {role_id!r} does not exist")
    return {"message": "Role deleted", "role_id": role_id}


# ---------------------------------------------------------------------------
# assignments
# ---------------------------------------------------------------------------

@rbac_router.post("/assignments", status_code=status.HTTP_201_CREATED)
async def assign_role(
    body: RoleAssignmentCreate,
    principal: Dict[str, Any] = Depends(get_v2_principal),
    rbac: RBACManager = Depends(get_rbac_manager),
) -> Dict[str, Any]:
    """Assign a role; ``granted_by`` is the authenticated principal."""
    return await rbac.assign_role(
        body.user_id,
        body.role_id,
        scope_type=body.scope_type,
        scope_id=body.scope_id,
        granted_by=str(principal["id"]),
        expires_at=body.expires_at,
    )


@rbac_router.delete("/assignments/{assignment_id}")
async def revoke_assignment(
    assignment_id: str,
    rbac: RBACManager = Depends(get_rbac_manager),
) -> Dict[str, Any]:
    """Revoke (delete) a role assignment."""
    if not await rbac.revoke_assignment(assignment_id):
        raise NotFoundError(f"Assignment {assignment_id!r} does not exist")
    return {"message": "Assignment revoked", "assignment_id": assignment_id}


@rbac_router.get("/users/{user_id}/assignments")
async def list_user_assignments(
    user_id: str,
    include_expired: bool = Query(default=False),
    rbac: RBACManager = Depends(get_rbac_manager),
) -> Dict[str, Any]:
    """A user's role assignments (expired ones hidden by default)."""
    assignments = await rbac.get_user_assignments(
        user_id, include_expired=include_expired
    )
    return {"user_id": user_id, "assignments": assignments, "total": len(assignments)}


@rbac_router.get("/users/{user_id}/roles")
async def get_user_roles(
    user_id: str,
    scope_type: PermissionScope = Query(default=PermissionScope.GLOBAL),
    scope_id: Optional[str] = Query(default=None),
    rbac: RBACManager = Depends(get_rbac_manager),
) -> Dict[str, Any]:
    """Effective roles for a user in a scope."""
    roles = await rbac.get_user_roles(user_id, scope_type, scope_id)
    return {"user_id": user_id, "roles": roles, "total": len(roles)}


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------

@rbac_router.post("/check-permission")
async def check_permission(
    body: PermissionCheckRequest,
    rbac: RBACManager = Depends(get_rbac_manager),
) -> Dict[str, Any]:
    """Check one permission (inheritance + wildcards + expiry)."""
    allowed = await rbac.has_permission(
        body.user_id, body.permission, body.scope_type, body.scope_id
    )
    return {
        "allowed": allowed,
        "user_id": body.user_id,
        "permission": body.permission,
        "scope_type": body.scope_type.value,
        "scope_id": body.scope_id,
    }


@rbac_router.get("/users/{user_id}/permissions")
async def get_user_permissions(
    user_id: str,
    scope_type: PermissionScope = Query(default=PermissionScope.GLOBAL),
    scope_id: Optional[str] = Query(default=None),
    rbac: RBACManager = Depends(get_rbac_manager),
) -> Dict[str, Any]:
    """All effective permission names for a user in a scope."""
    permissions = await rbac.get_effective_permissions(
        user_id, scope_type, scope_id
    )
    return {"user_id": user_id, "permissions": permissions}
