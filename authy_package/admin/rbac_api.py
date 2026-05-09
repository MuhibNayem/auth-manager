"""
Authy Enterprise RBAC API
FastAPI endpoints for Role & Permission Management.
"""

from fastapi import APIRouter, HTTPException, Depends, Body, Request
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# Assuming these are imported from your existing setup
# from authy_package.admin.rbac_manager import RBACManager, PermissionScope
from .rbac_manager import RBACManager, PermissionScope

router = APIRouter(prefix="/admin/v2/rbac", tags=["RBAC"])

# --- Pydantic Models ---

class PermissionCreate(BaseModel):
    name: str = Field(..., description="e.g., 'user:create'")
    description: str
    category: str = Field(..., description="e.g., 'users', 'billing'")
    scope: PermissionScope = PermissionScope.GLOBAL

class PermissionResponse(PermissionCreate):
    id: str
    created_at: datetime

class RoleCreate(BaseModel):
    name: str
    description: str
    permissions: List[str] = Field(default_factory=list)  # List of permission IDs
    inherits_from: Optional[str] = None
    organization_id: Optional[str] = None

class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = None

class RoleResponse(RoleCreate):
    id: str
    is_system: bool
    created_at: datetime
    updated_at: datetime

class RoleAssignmentCreate(BaseModel):
    user_id: str
    role_id: str
    scope_type: PermissionScope
    scope_id: Optional[str] = None
    expires_at: Optional[datetime] = None

class RoleAssignmentResponse(RoleAssignmentCreate):
    id: str
    granted_by: str
    created_at: datetime

class PermissionCheckRequest(BaseModel):
    user_id: str
    permission: str
    scope_type: PermissionScope
    scope_id: Optional[str] = None

class PermissionCheckResponse(BaseModel):
    allowed: bool
    details: Optional[str] = None

# --- Dependency Injection ---

def get_rbac_manager(request: Request) -> RBACManager:
    rbac_manager = getattr(request.app.state, "rbac_manager", None)
    if not rbac_manager:
        raise HTTPException(status_code=500, detail="RBAC manager not configured")
    return rbac_manager

# --- Permission Endpoints ---

@router.post("/permissions", response_model=PermissionResponse, status_code=201)
async def create_permission(perm: PermissionCreate, rbac: RBACManager = Depends(get_rbac_manager)):
    """Create a new granular permission."""
    try:
        new_perm = await rbac.create_permission(
            name=perm.name,
            description=perm.description,
            category=perm.category,
            scope=perm.scope
        )
        return PermissionResponse(**new_perm.__dict__)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/permissions", response_model=List[PermissionResponse])
async def list_permissions(category: Optional[str] = None, rbac: RBACManager = Depends(get_rbac_manager)):
    """List all permissions, optionally filtered by category."""
    perms = await rbac.list_permissions(category=category)
    return [PermissionResponse(**p.__dict__) for p in perms]

# --- Role Endpoints ---

@router.post("/roles", response_model=RoleResponse, status_code=201)
async def create_role(role: RoleCreate, rbac: RBACManager = Depends(get_rbac_manager)):
    """Create a new custom role."""
    try:
        new_role = await rbac.create_role(
            name=role.name,
            description=role.description,
            permissions=role.permissions,
            inherits_from=role.inherits_from,
            organization_id=role.organization_id
        )
        return RoleResponse(**new_role.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/roles", response_model=List[RoleResponse])
async def list_roles(organization_id: Optional[str] = None, rbac: RBACManager = Depends(get_rbac_manager)):
    """List roles (global or org-specific)."""
    roles = await rbac.list_roles(organization_id=organization_id)
    return [RoleResponse(**r.__dict__) for r in roles]

@router.put("/roles/{role_id}", response_model=RoleResponse)
async def update_role(role_id: str, role_update: RoleUpdate, rbac: RBACManager = Depends(get_rbac_manager)):
    """Update an existing custom role."""
    try:
        updated_role = await rbac.update_role(
            role_id=role_id,
            name=role_update.name,
            description=role_update.description,
            permissions=role_update.permissions
        )
        return RoleResponse(**updated_role.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))

@router.delete("/roles/{role_id}", status_code=204)
async def delete_role(role_id: str, rbac: RBACManager = Depends(get_rbac_manager)):
    """Delete a custom role (if not in use and not system)."""
    try:
        await rbac.delete_role(role_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))

# --- Assignment Endpoints ---

@router.post("/assignments", response_model=RoleAssignmentResponse, status_code=201)
async def assign_role(assignment: RoleAssignmentCreate, rbac: RBACManager = Depends(get_rbac_manager)):
    """Assign a role to a user within a specific scope."""
    # In real app, get current user ID from auth context
    current_user_id = "admin_user_id_placeholder" 
    
    try:
        new_assignment = await rbac.assign_role(
            user_id=assignment.user_id,
            role_id=assignment.role_id,
            scope_type=assignment.scope_type,
            scope_id=assignment.scope_id,
            granted_by=current_user_id,
            expires_at=assignment.expires_at
        )
        return RoleAssignmentResponse(**new_assignment.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/assignments/{assignment_id}", status_code=204)
async def revoke_role(assignment_id: str, rbac: RBACManager = Depends(get_rbac_manager)):
    """Revoke a role assignment."""
    try:
        await rbac.revoke_role(assignment_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/users/{user_id}/roles")
async def get_user_roles(user_id: str, scope_type: PermissionScope, scope_id: Optional[str] = None, rbac: RBACManager = Depends(get_rbac_manager)):
    """Get all roles assigned to a user in a specific scope."""
    roles = await rbac.get_user_roles(user_id, scope_type, scope_id)
    return [RoleResponse(**r.__dict__) for r in roles]

# --- Evaluation Endpoints ---

@router.post("/check-permission", response_model=PermissionCheckResponse)
async def check_permission(req: PermissionCheckRequest, rbac: RBACManager = Depends(get_rbac_manager)):
    """Check if a user has a specific permission."""
    allowed = await rbac.has_permission(
        user_id=req.user_id,
        permission_name=req.permission,
        scope_type=req.scope_type,
        scope_id=req.scope_id
    )
    return PermissionCheckResponse(allowed=allowed)

@router.get("/users/{user_id}/permissions")
async def get_user_permissions(user_id: str, scope_type: PermissionScope, scope_id: Optional[str] = None, rbac: RBACManager = Depends(get_rbac_manager)):
    """Get all effective permissions for a user."""
    perms = await rbac.get_effective_permissions(user_id, scope_type, scope_id)
    return {"permissions": perms}
