"""RBAC tests: grants, checks, inheritance, time-limited assignments."""

from __future__ import annotations

from datetime import timedelta, timezone, datetime

import pytest
import pytest_asyncio

from tessera.admin.rbac_manager import PermissionScope, RBACManager


@pytest_asyncio.fixture
async def rbac(db) -> RBACManager:
    return await RBACManager.create(db)


@pytest.mark.asyncio
async def test_grant_check_and_expiry(rbac, db):
    role = await rbac.create_role("auditor", "Read audits", ["audit:read"])
    user = await db.create_user({"email": "auditor@example.com"})

    # No grant yet → denied.
    assert await rbac.has_permission(user["id"], "audit:read") is False

    assignment = await rbac.assign_role(
        user["id"],
        role["id"],
        scope_type=PermissionScope.GLOBAL,
        granted_by="admin-1",
    )
    assert assignment["granted_by"] == "admin-1"
    assert await rbac.has_permission(user["id"], "audit:read") is True
    assert await rbac.has_permission(user["id"], "user:delete") is False

    # Time-limited assignment stops granting once expired.
    limited_role = await rbac.create_role("temp", "Temp", ["user:update"])
    expired_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await rbac.assign_role(
        user["id"],
        limited_role["id"],
        scope_type=PermissionScope.GLOBAL,
        granted_by="admin-1",
        expires_at=expired_at,
    )
    assert await rbac.has_permission(user["id"], "user:update") is False

    future_at = datetime.now(timezone.utc) + timedelta(hours=1)
    await rbac.assign_role(
        user["id"],
        limited_role["id"],
        scope_type=PermissionScope.GLOBAL,
        granted_by="admin-1",
        expires_at=future_at,
    )
    assert await rbac.has_permission(user["id"], "user:update") is True


@pytest.mark.asyncio
async def test_inheritance_and_wildcard_and_cycle_guard(rbac, db):
    base = await rbac.create_role("base", "Base", ["audit:read"])
    child = await rbac.create_role("child", "Child", ["user:read"], inherits_from=base["id"])
    admin_role = await rbac.create_role("super", "Super", ["admin:*"])
    user = await db.create_user({"email": "heir@example.com"})

    await rbac.assign_role(user["id"], child["id"], granted_by="admin-1")
    # Inherited from base.
    assert await rbac.has_permission(user["id"], "audit:read") is True
    assert await rbac.has_permission(user["id"], "user:read") is True

    await rbac.assign_role(user["id"], admin_role["id"], granted_by="admin-1")
    # Wildcard admin:* covers admin:anything.
    assert await rbac.has_permission(user["id"], "admin:users") is True

    # Cycle guard: making base inherit from its descendant is refused.
    with pytest.raises(ValueError):
        await rbac.update_role(base["id"], inherits_from=child["id"])


@pytest.mark.asyncio
async def test_scoped_assignments_only_apply_to_their_scope(rbac, db):
    org_role = await rbac.create_role("org-admin", "Org admin", ["org:manage"])
    user = await db.create_user({"email": "scoped@example.com"})
    await rbac.assign_role(
        user["id"],
        org_role["id"],
        scope_type=PermissionScope.ORGANIZATION,
        scope_id="org-1",
        granted_by="admin-1",
    )
    assert (
        await rbac.has_permission(
            user["id"], "org:manage", PermissionScope.ORGANIZATION, "org-1"
        )
        is True
    )
    assert (
        await rbac.has_permission(
            user["id"], "org:manage", PermissionScope.ORGANIZATION, "org-2"
        )
        is False
    )


@pytest.mark.asyncio
async def test_system_role_protection(rbac):
    system = await rbac.create_role("admin", "Built-in admin", ["admin:*"], is_system=True)
    with pytest.raises(PermissionError):
        await rbac.update_role(system["id"], description="nope")
    with pytest.raises(PermissionError):
        await rbac.delete_role(system["id"])


@pytest.mark.asyncio
async def test_rbac_api_granted_by_from_principal(client, admin_headers, admin_user, db):
    role = await client.post(
        "/admin/v2/rbac/roles",
        headers=admin_headers,
        json={"name": "viewer", "description": "Read-only", "permissions": ["read:only"]},
    )
    assert role.status_code == 201, role.text
    role_id = role.json()["id"]

    target = await db.create_user({"email": "assignee@example.com"})
    assignment = await client.post(
        "/admin/v2/rbac/assignments",
        headers=admin_headers,
        json={"user_id": target["id"], "role_id": role_id},
    )
    assert assignment.status_code == 201, assignment.text
    # granted_by must be the authenticated admin, not a placeholder.
    assert assignment.json()["granted_by"] == admin_user["id"]

    check = await client.post(
        "/admin/v2/rbac/check-permission",
        headers=admin_headers,
        json={"user_id": target["id"], "permission": "read:only"},
    )
    assert check.status_code == 200
    assert check.json()["allowed"] is True


@pytest.mark.asyncio
async def test_rbac_api_requires_auth(client):
    response = await client.get("/admin/v2/rbac/roles")
    assert response.status_code == 401
