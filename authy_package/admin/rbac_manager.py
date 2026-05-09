"""
Authy Enterprise RBAC Engine
State-of-the-Art Role-Based Access Control with Hierarchies, Granular Permissions, and Resource Scoping.
"""

from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime
import uuid
from enum import Enum

# --- Core Data Models ---

class PermissionScope(str, Enum):
    GLOBAL = "global"
    ORGANIZATION = "organization"
    TEAM = "team"
    RESOURCE = "resource"

@dataclass
class Permission:
    """Granular permission definition."""
    id: str
    name: str  # e.g., "user:create"
    description: str
    category: str  # e.g., "users", "billing", "audit"
    scope: PermissionScope = PermissionScope.GLOBAL
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class Role:
    """Role definition with inheritance and permissions."""
    id: str
    name: str
    description: str
    permissions: Set[str] = field(default_factory=set)  # Set of Permission IDs
    inherits_from: Optional[str] = None  # ID of parent role
    is_system: bool = False  # System roles (Admin, Owner) cannot be deleted
    organization_id: Optional[str] = None  # Null = global role
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class RoleAssignment:
    """Assignment of a role to a user within a specific scope."""
    id: str
    user_id: str
    role_id: str
    scope_type: PermissionScope
    scope_id: Optional[str] = None  # Org ID or Team ID if scoped
    granted_by: str
    expires_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

# --- RBAC Engine ---

class RBACManager:
    """
    High-performance RBAC engine with support for:
    - Dynamic role creation
    - Permission inheritance
    - Resource scoping
    - Real-time evaluation
    """
    
    def __init__(self, db_interface):
        self.db = db_interface
        self._permission_cache: Dict[str, Permission] = {}
        self._role_cache: Dict[str, Role] = {}
        self._load_cache()

    def _load_cache(self):
        """Pre-load roles and permissions for fast evaluation."""
        # In production, this would load from Redis/DB
        pass

    @staticmethod
    def _serialize_role(role: Role) -> Dict[str, Any]:
        role_data = role.__dict__.copy()
        role_data["permissions"] = list(role.permissions)
        role_data["created_at"] = role.created_at.isoformat()
        role_data["updated_at"] = role.updated_at.isoformat()
        return role_data

    @staticmethod
    def _serialize_assignment(assignment: RoleAssignment) -> Dict[str, Any]:
        assignment_data = assignment.__dict__.copy()
        assignment_data["scope_type"] = assignment.scope_type.value
        assignment_data["created_at"] = assignment.created_at.isoformat()
        assignment_data["expires_at"] = assignment.expires_at.isoformat() if assignment.expires_at else None
        return assignment_data

    # --- Permission Management ---

    async def create_permission(self, name: str, description: str, category: str, scope: PermissionScope = PermissionScope.GLOBAL) -> Permission:
        perm_id = f"perm_{uuid.uuid4().hex[:8]}"
        permission = Permission(id=perm_id, name=name, description=description, category=category, scope=scope)
        await self.db.save("permissions", perm_id, permission.__dict__)
        self._permission_cache[perm_id] = permission
        return permission

    async def list_permissions(self, category: Optional[str] = None) -> List[Permission]:
        if category:
            return [p for p in self._permission_cache.values() if p.category == category]
        return list(self._permission_cache.values())

    # --- Role Management ---

    async def create_role(self, name: str, description: str, permissions: List[str], inherits_from: Optional[str] = None, organization_id: Optional[str] = None, is_system: bool = False) -> Role:
        role_id = f"role_{uuid.uuid4().hex[:8]}"
        
        # Validate inheritance
        if inherits_from and inherits_from not in self._role_cache:
            raise ValueError(f"Parent role {inherits_from} not found")

        role = Role(
            id=role_id,
            name=name,
            description=description,
            permissions=set(permissions),
            inherits_from=inherits_from,
            is_system=is_system,
            organization_id=organization_id
        )
        
        await self.db.save("roles", role_id, self._serialize_role(role))
        self._role_cache[role_id] = role
        return role

    async def update_role(self, role_id: str, name: Optional[str] = None, permissions: Optional[List[str]] = None, description: Optional[str] = None):
        if role_id not in self._role_cache:
            raise ValueError("Role not found")
        
        role = self._role_cache[role_id]
        if role.is_system:
            raise PermissionError("Cannot modify system roles")

        if name: role.name = name
        if description: role.description = description
        if permissions is not None: role.permissions = set(permissions)
        
        role.updated_at = datetime.utcnow()
        await self.db.save("roles", role_id, self._serialize_role(role))
        self._role_cache[role_id] = role
        return role

    async def delete_role(self, role_id: str):
        if role_id not in self._role_cache:
            raise ValueError("Role not found")
        
        role = self._role_cache[role_id]
        if role.is_system:
            raise PermissionError("Cannot delete system roles")
        
        # Check if role is in use
        assignments = await self.db.query("role_assignments", {"role_id": role_id})
        if assignments:
            raise ValueError("Cannot delete role assigned to users")

        del self._role_cache[role_id]
        await self.db.delete("roles", role_id)

    async def list_roles(self, organization_id: Optional[str] = None) -> List[Role]:
        roles = list(self._role_cache.values())
        if organization_id:
            # Return global roles + org-specific roles
            return [r for r in roles if r.organization_id is None or r.organization_id == organization_id]
        return [r for r in roles if r.organization_id is None] # Global only if no org specified

    # --- Assignment Management ---

    async def assign_role(self, user_id: str, role_id: str, scope_type: PermissionScope, scope_id: Optional[str], granted_by: str, expires_at: Optional[datetime] = None) -> RoleAssignment:
        if role_id not in self._role_cache:
            raise ValueError("Role not found")

        assignment_id = f"assign_{uuid.uuid4().hex[:8]}"
        assignment = RoleAssignment(
            id=assignment_id,
            user_id=user_id,
            role_id=role_id,
            scope_type=scope_type,
            scope_id=scope_id,
            granted_by=granted_by,
            expires_at=expires_at
        )
        
        await self.db.save("role_assignments", assignment_id, self._serialize_assignment(assignment))
        return assignment

    async def revoke_role(self, assignment_id: str):
        await self.db.delete("role_assignments", assignment_id)

    async def get_user_roles(self, user_id: str, scope_type: PermissionScope, scope_id: Optional[str]) -> List[Role]:
        """Get all effective roles for a user in a specific scope."""
        assignments = await self.db.query("role_assignments", {
            "user_id": user_id,
            "scope_type": scope_type.value,
            "scope_id": scope_id
        })
        if not assignments:
            assignments = await self.db.query("role_assignments", {
                "user_id": user_id,
                "scope_type": scope_type,
                "scope_id": scope_id
            })
        
        roles = []
        for assign in assignments:
            expires_at = assign.get('expires_at')
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            if expires_at and expires_at < datetime.utcnow():
                continue # Expired
            
            role_id = assign['role_id']
            if role_id in self._role_cache:
                roles.append(self._role_cache[role_id])
        
        return roles

    # --- Evaluation Engine (The Core) ---

    async def has_permission(self, user_id: str, permission_name: str, scope_type: PermissionScope, scope_id: Optional[str]) -> bool:
        """
        Check if a user has a specific permission in a given scope.
        Resolves inheritance and aggregates permissions from all assigned roles.
        """
        roles = await self.get_user_roles(user_id, scope_type, scope_id)
        
        # Collect all permissions (direct + inherited)
        effective_permissions: Set[str] = set()
        
        def resolve_role_perms(role: Role, visited: Set[str]):
            if role.id in visited:
                return # Prevent circular inheritance
            visited.add(role.id)
            
            effective_permissions.update(role.permissions)
            
            if role.inherits_from and role.inherits_from in self._role_cache:
                parent = self._role_cache[role.inherits_from]
                resolve_role_perms(parent, visited)

        for role in roles:
            resolve_role_perms(role, set())

        # Map permission name to ID (simple lookup for demo, usually indexed)
        perm_id = next((p.id for p in self._permission_cache.values() if p.name == permission_name), None)
        
        return perm_id in effective_permissions if perm_id else False

    async def get_effective_permissions(self, user_id: str, scope_type: PermissionScope, scope_id: Optional[str]) -> List[str]:
        """Return list of all permission names a user has."""
        roles = await self.get_user_roles(user_id, scope_type, scope_id)
        perm_ids = set()
        
        def resolve_role_perms(role: Role, visited: Set[str]):
            if role.id in visited: return
            visited.add(role.id)
            perm_ids.update(role.permissions)
            if role.inherits_from and role.inherits_from in self._role_cache:
                resolve_role_perms(self._role_cache[role.inherits_from], visited)

        for role in roles:
            resolve_role_perms(role, set())
            
        return [p.name for p in self._permission_cache.values() if p.id in perm_ids]

# --- Default System Roles Seeder ---

async def seed_system_roles(rbac: RBACManager):
    """Create default system roles if they don't exist."""
    # Define standard permissions
    perms = [
        ("user:read", "View user details", "users"),
        ("user:create", "Create new users", "users"),
        ("user:update", "Update user details", "users"),
        ("user:delete", "Delete users", "users"),
        ("role:manage", "Manage roles and permissions", "settings"),
        ("audit:read", "View audit logs", "audit"),
        ("audit:export", "Export audit logs", "audit"),
        ("billing:read", "View billing info", "billing"),
        ("billing:manage", "Manage billing", "billing"),
    ]
    
    created_perms = {}
    for name, desc, cat in perms:
        p = await rbac.create_permission(name, desc, cat)
        created_perms[name] = p.id

    # Create Owner Role (Inherits nothing, has all)
    await rbac.create_role(
        name="Owner",
        description="Full access to everything",
        permissions=list(created_perms.values()),
        is_system=True
    )

    # Create Admin Role (Inherits Member, adds management)
    # Note: In a real DB, we'd need IDs first. Simplified here.
    # This is a conceptual seeder.
