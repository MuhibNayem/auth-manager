"""Admin dashboard API v1 (CONTRACTS.md §5).

Rebuilt wiring:

- :class:`~tessera.admin.deps.AdminDependencies` on ``app.state``;
  every route resolves services through ``Depends``.
- Bearer-only authentication via ``HTTPBearer`` — tokens are NEVER read
  from query parameters.
- ``POST /auth/login`` issues real JWTs through
  :class:`~tessera.utils.security.JWTTokenManager`, enforces the §3.1
  rate-limit/lockout helpers and writes audit events.
- ``POST /auth/refresh`` implements refresh-token rotation (§3.1).
- User CRUD/search/bulk over the §4 db contract with pagination totals.
- Organizations via :class:`OrganizationManager`; org-scoped routes enforce
  :func:`require_org_admin`.
- Audit search/export via ``db.search_audit_events`` (CSV uses ``csv``
  module ``QUOTE_ALL``); sessions via the db contract; webhooks via
  :class:`WebhookManager`; health via ``db.health_check`` +
  ``cache.health_check``.
- Impersonation: audit-logged, 15-minute TTL token, privileged targets
  (admin/owner/superadmin) refused.
- TesseraError → HTTP status mapping is registered by
  :func:`install_admin_api`.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional

import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field

from tessera.admin.audit_logger import AuditLogger, EventType
from tessera.admin.deps import (
    ADMIN_ROLES,
    AdminDependencies,
    get_admin_deps,
    get_current_admin_user,
    register_error_handlers,
    require_org_admin,
)
from tessera.errors import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    TokenError,
)
from tessera.utils.security import (
    clear_login_failures,
    enforce_login_rate_limit,
    hash_password,
    record_login_failure,
    verify_password_constant_time,
)

logger = logging.getLogger("tessera.admin.dashboard")

__all__ = ["admin_router", "install_admin_api", "create_admin_app"]

#: Impersonation token lifetime (§5: 15 minutes).
IMPERSONATION_TTL_SECONDS = 15 * 60

#: Upper bound for bulk user operations (422 above this).
MAX_BULK_USER_IDS = 1000

admin_router = APIRouter(prefix="/admin/api/v1", tags=["Admin Dashboard"])


# ---------------------------------------------------------------------------
# request schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    """Admin login payload expected by the UI kit."""

    username_or_email: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=1)


class UserCreateSchema(BaseModel):
    username: Optional[str] = None
    email: str = Field(..., min_length=3)
    phone: Optional[str] = None
    password: str = Field(..., min_length=8)
    role: str = "user"
    organization_id: Optional[str] = None


class UserUpdateSchema(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class BulkUserOperation(BaseModel):
    user_ids: List[str] = Field(..., min_length=1)
    action: Literal["activate", "deactivate", "lock", "unlock", "delete"]
    reason: Optional[str] = None


class OrganizationCreateSchema(BaseModel):
    name: str = Field(..., min_length=1)
    description: Optional[str] = None
    plan: str = "free"
    owner_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class MemberAddSchema(BaseModel):
    user_id: str = Field(..., min_length=1)
    role: str = "member"


class MemberRoleUpdateSchema(BaseModel):
    role: Literal["owner", "admin", "member", "guest"]


class InvitationCreateSchema(BaseModel):
    email: str = Field(..., min_length=3)
    role: str = "member"
    expires_in_hours: Optional[int] = Field(default=72, ge=1, le=24 * 30)
    message: Optional[str] = None


class InvitationAcceptSchema(BaseModel):
    token: str = Field(..., min_length=1)
    user_id: Optional[str] = None


class WebhookEndpointCreate(BaseModel):
    url: str = Field(..., min_length=1)
    events: List[str] = Field(default_factory=list)  # [] = subscribe-all (§7)
    description: Optional[str] = None
    enabled: bool = True


class WebhookEndpointUpdate(BaseModel):
    url: Optional[str] = None
    events: Optional[List[str]] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _sanitize_user(user: Dict[str, Any]) -> Dict[str, Any]:
    """Strip credential material from a user document."""
    view = dict(user)
    view.pop("hashed_password", None)
    view.pop("mfa_secret", None)
    return view


def _client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


async def _audit(
    deps: AdminDependencies,
    event_type: EventType,
    action: str,
    *,
    actor_id: Optional[str] = None,
    target_id: Optional[str] = None,
    target_type: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    severity: str = "info",
    audit_status: str = "success",
) -> None:
    """Write an audit event when a logger is configured (always sync)."""
    if deps.audit_logger is None:
        return
    await deps.audit_logger.log(
        event_type,
        action,
        actor_id=actor_id,
        target_id=target_id,
        target_type=target_type,
        metadata=metadata,
        ip_address=ip_address,
        severity=severity,
        status=audit_status,
        sync=True,
    )


def _require_orgs(deps: AdminDependencies):
    if deps.orgs is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Organization service not configured",
        )
    return deps.orgs


def _require_webhooks(deps: AdminDependencies):
    if deps.webhooks is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhook service not configured",
        )
    return deps.webhooks


def _issue_impersonation_token(
    deps: AdminDependencies, admin_user: Dict[str, Any], target_user: Dict[str, Any]
) -> str:
    """Sign a 15-minute access token marked as an impersonation session.

    Built with the same secret/algorithm/issuer/audience as
    :class:`JWTTokenManager` so it validates through the normal path, with
    an explicit short TTL and ``impersonation`` claims.
    """
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": target_user["id"],
        "type": "access",
        "jti": secrets.token_urlsafe(16),
        "iat": now,
        "exp": now + timedelta(seconds=IMPERSONATION_TTL_SECONDS),
        "impersonation": True,
        "impersonator": admin_user["id"],
    }
    if deps.config.jwt_issuer:
        payload["iss"] = deps.config.jwt_issuer
    if deps.config.jwt_audience:
        payload["aud"] = deps.config.jwt_audience
    return pyjwt.encode(payload, deps.config.jwt_secret, algorithm=deps.config.jwt_algorithm)


# ---------------------------------------------------------------------------
# auth: login + refresh
# ---------------------------------------------------------------------------

@admin_router.post("/auth/login")
async def admin_login(
    body: LoginRequest,
    request: Request,
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Authenticate an admin user and issue an access/refresh pair.

    Accepts ``{username_or_email, password}``; returns
    ``{access_token, refresh_token, token_type, expires_in, user}`` (the
    shape expected by the dashboard UI kit). Failed attempts feed the §3.1
    rate-limit/lockout counters; failures are indistinguishable for
    bad-user vs bad-password.
    """
    identifier = body.username_or_email.strip()
    normalized = identifier.lower()
    ip_address = _client_ip(request)

    await enforce_login_rate_limit(deps.cache, normalized, config=deps.config)

    user = await deps.db.get_user_by_identifier(
        email=identifier, username=identifier
    )
    password_ok = verify_password_constant_time(
        body.password,
        user.get("hashed_password") if user else None,
        algorithm=deps.config.password_hash_algorithm,
        bcrypt_rounds=deps.config.bcrypt_rounds,
    )
    if user is None or not password_ok or not user.get("is_active", True):
        await record_login_failure(deps.cache, normalized, config=deps.config)
        await _audit(
            deps,
            EventType.LOGIN_FAILED,
            "Admin login failed",
            actor_id=user["id"] if user else None,
            metadata={"identifier": normalized},
            ip_address=ip_address,
            severity="warning",
            audit_status="failure",
        )
        raise AuthenticationError("Invalid credentials")

    role = str(user.get("role", "user"))
    rbac_admin = False
    if deps.rbac is not None:
        rbac_admin = await deps.rbac.has_permission(user["id"], "admin:*")
    if role not in ADMIN_ROLES and not rbac_admin:
        await _audit(
            deps,
            EventType.LOGIN_FAILED,
            "Admin login denied: insufficient role",
            actor_id=user["id"],
            ip_address=ip_address,
            severity="warning",
            audit_status="failure",
        )
        raise AuthorizationError("Admin access required")

    await clear_login_failures(deps.cache, normalized, config=deps.config)

    pair = deps.token_manager.create_token_pair(user["id"])
    await deps.cache.set(
        f"tessera:refresh:{pair['refresh_jti']}",
        user["id"],
        ttl_seconds=deps.config.refresh_token_ttl_seconds,
    )
    session_id = secrets.token_hex(16)
    await deps.db.save_session(
        {
            "id": session_id,
            "user_id": user["id"],
            "access_jti": pair["access_jti"],
            "refresh_jti": pair["refresh_jti"],
            "ip_address": ip_address,
            "user_agent": request.headers.get("user-agent"),
            "status": "active",
            "created_at": datetime.now(timezone.utc),
        }
    )
    await _audit(
        deps,
        EventType.LOGIN_SUCCESS,
        "Admin login successful",
        actor_id=user["id"],
        target_id=session_id,
        target_type="session",
        ip_address=ip_address,
    )
    await _audit(
        deps,
        EventType.SESSION_CREATED,
        "Admin session created",
        actor_id=user["id"],
        target_id=session_id,
        target_type="session",
        ip_address=ip_address,
    )

    return {
        "access_token": pair["access_token"],
        "refresh_token": pair["refresh_token"],
        "token_type": "bearer",
        "expires_in": deps.config.access_token_ttl_seconds,
        "user": _sanitize_user(user),
    }


@admin_router.post("/auth/refresh")
async def admin_refresh(
    body: RefreshRequest,
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Rotate a refresh token (§3.1 delete-then-create).

    The old refresh jti is verified against the cache and deleted BEFORE
    the new pair is issued; replaying an old refresh token fails.
    """
    try:
        payload = deps.token_manager.validate_token(
            body.refresh_token, expected_type="refresh"
        )
    except TokenError as exc:
        raise AuthenticationError(exc.message, code=exc.code) from exc

    user_id = payload["sub"]
    old_jti = payload["jti"]
    stored = await deps.cache.get(f"tessera:refresh:{old_jti}")
    if stored != user_id:
        raise AuthenticationError(
            "Refresh token has been revoked or already rotated",
            code="token_revoked",
        )

    user = await deps.db.get_user_by_id(user_id)
    if user is None or not user.get("is_active", True):
        raise AuthenticationError("Invalid credentials")

    await deps.cache.delete(f"tessera:refresh:{old_jti}")
    pair = deps.token_manager.create_token_pair(user_id)
    await deps.cache.set(
        f"tessera:refresh:{pair['refresh_jti']}",
        user_id,
        ttl_seconds=deps.config.refresh_token_ttl_seconds,
    )
    return {
        "access_token": pair["access_token"],
        "refresh_token": pair["refresh_token"],
        "token_type": "bearer",
        "expires_in": deps.config.access_token_ttl_seconds,
    }


# ---------------------------------------------------------------------------
# user management
# ---------------------------------------------------------------------------

@admin_router.get("/users")
async def list_users(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    search: Optional[str] = None,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Paginated user listing with search and filters; includes totals."""
    filters: Dict[str, Any] = {}
    if role is not None:
        filters["role"] = role
    if is_active is not None:
        filters["is_active"] = is_active
    rows, total = await deps.db.list_users(
        limit=page_size,
        offset=(page - 1) * page_size,
        search=search,
        filters=filters or None,
    )
    return {
        "users": [_sanitize_user(row) for row in rows],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size if total else 0,
        },
    }


@admin_router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreateSchema,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Create a user (password hashed per config)."""
    hashed = hash_password(
        body.password,
        algorithm=deps.config.password_hash_algorithm,
        bcrypt_rounds=deps.config.bcrypt_rounds,
    )
    user = await deps.db.create_user(
        {
            "username": body.username,
            "email": body.email,
            "phone": body.phone,
            "hashed_password": hashed,
            "role": body.role,
            "is_active": True,
            "mfa_enabled": False,
        }
    )
    if body.organization_id and deps.orgs is not None:
        await deps.orgs.add_member(
            body.organization_id, user["id"], "member", added_by=current_user["id"]
        )
    await _audit(
        deps,
        EventType.USER_CREATED,
        f"User created by admin: {user['id']}",
        actor_id=current_user["id"],
        target_id=user["id"],
        target_type="user",
        metadata={"email": body.email},
        ip_address=_client_ip(request),
    )
    return _sanitize_user(user)


@admin_router.get("/users/{user_id}")
async def get_user(
    user_id: str,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Fetch one user (404 when missing)."""
    user = await deps.db.get_user_by_id(user_id)
    if user is None:
        raise NotFoundError(f"User {user_id!r} does not exist")
    return _sanitize_user(user)


@admin_router.put("/users/{user_id}")
async def update_user(
    user_id: str,
    body: UserUpdateSchema,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Partial user update (whitelisted fields only)."""
    updates = body.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    user = await deps.db.update_user(user_id, updates)
    if user is None:
        raise NotFoundError(f"User {user_id!r} does not exist")
    await _audit(
        deps,
        EventType.USER_UPDATED,
        f"User updated by admin: {user_id}",
        actor_id=current_user["id"],
        target_id=user_id,
        target_type="user",
        metadata={"fields": sorted(updates)},
        ip_address=_client_ip(request),
    )
    return _sanitize_user(user)


@admin_router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Delete a user and revoke all of their sessions."""
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    user = await deps.db.get_user_by_id(user_id)
    if user is None:
        raise NotFoundError(f"User {user_id!r} does not exist")
    await deps.db.revoke_all_user_sessions(user_id)
    await deps.db.delete_user(user_id)
    await _audit(
        deps,
        EventType.USER_DELETED,
        f"User deleted by admin: {user_id}",
        actor_id=current_user["id"],
        target_id=user_id,
        target_type="user",
        metadata={"email": user.get("email")},
        ip_address=_client_ip(request),
        severity="warning",
    )
    return {"message": "User deleted successfully", "user_id": user_id}



@admin_router.post("/users/bulk")
async def bulk_user_operation(
    operation: BulkUserOperation,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Bulk activate/deactivate/lock/unlock/delete users.

    ``user_ids`` is bounded: more than 1000 ids is rejected with 422.
    Every applied action emits an audit event.
    """
    if len(operation.user_ids) > MAX_BULK_USER_IDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Bulk operations are limited to {MAX_BULK_USER_IDS} user_ids",
        )

    succeeded: List[str] = []
    failed: List[Dict[str, Any]] = []
    for user_id in operation.user_ids:
        try:
            if operation.action == "delete":
                if user_id == current_user["id"]:
                    failed.append({"user_id": user_id, "reason": "Cannot delete self"})
                    continue
                await deps.db.revoke_all_user_sessions(user_id)
                if not await deps.db.delete_user(user_id):
                    failed.append({"user_id": user_id, "reason": "User not found"})
                    continue
            else:
                if operation.action in ("activate", "unlock"):
                    updates = {"is_active": True}
                else:  # deactivate | lock
                    updates = {"is_active": False}
                updated = await deps.db.update_user(user_id, updates)
                if updated is None:
                    failed.append({"user_id": user_id, "reason": "User not found"})
                    continue
                if operation.action == "lock":
                    await deps.db.revoke_all_user_sessions(user_id)
            succeeded.append(user_id)
            await _audit(
                deps,
                EventType.ADMIN_ACTION,
                f"Bulk {operation.action} applied to user {user_id}",
                actor_id=current_user["id"],
                target_id=user_id,
                target_type="user",
                metadata={"action": operation.action, "reason": operation.reason},
                ip_address=_client_ip(request),
                severity="warning" if operation.action == "delete" else "info",
            )
        except Exception as exc:  # noqa: BLE001 - continue batch on per-user error
            failed.append({"user_id": user_id, "reason": type(exc).__name__})
    return {
        "action": operation.action,
        "succeeded": succeeded,
        "failed": failed,
        "processed": len(succeeded),
    }


@admin_router.post("/users/{user_id}/impersonate")
async def impersonate_user(
    user_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Issue a 15-minute impersonation token (audit-logged).

    Impersonating users whose role is admin/owner/superadmin is refused.
    """
    target = await deps.db.get_user_by_id(user_id)
    if target is None:
        raise NotFoundError(f"User {user_id!r} does not exist")
    if str(target.get("role", "user")) in ADMIN_ROLES:
        raise AuthorizationError(
            "Cannot impersonate users with privileged roles (admin/owner/superadmin)"
        )
    token = _issue_impersonation_token(deps, current_user, target)
    await _audit(
        deps,
        EventType.USER_IMPERSONATION,
        f"Admin impersonated user {user_id}",
        actor_id=current_user["id"],
        target_id=user_id,
        target_type="user",
        metadata={"ttl_seconds": IMPERSONATION_TTL_SECONDS},
        ip_address=_client_ip(request),
        severity="warning",
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": IMPERSONATION_TTL_SECONDS,
        "impersonating": _sanitize_user(target),
        "original_admin_id": current_user["id"],
    }


# ---------------------------------------------------------------------------
# organizations
# ---------------------------------------------------------------------------

@admin_router.get("/organizations")
async def list_organizations(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    search: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Paginated organization listing."""
    orgs = _require_orgs(deps)
    rows, total = await orgs.get_organizations_paginated(
        page=page, page_size=page_size, search=search
    )
    return {
        "organizations": rows,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size if total else 0,
        },
    }


@admin_router.post("/organizations", status_code=status.HTTP_201_CREATED)
async def create_organization(
    body: OrganizationCreateSchema,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Create an organization; owner defaults to the acting admin."""
    orgs = _require_orgs(deps)
    owner_id = body.owner_id or current_user["id"]
    org = await orgs.create_organization(
        body.name,
        owner_id,
        description=body.description,
        plan=body.plan,
        metadata=body.metadata,
    )
    await _audit(
        deps,
        EventType.ORG_CREATED,
        f"Organization created: {org['name']}",
        actor_id=current_user["id"],
        target_id=org["id"],
        target_type="organization",
        ip_address=_client_ip(request),
    )
    return org


@admin_router.get("/organizations/{org_id}")
async def get_organization(
    org_id: str,
    current_user: Dict[str, Any] = Depends(require_org_admin),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Organization detail incl. members and pending invitations."""
    orgs = _require_orgs(deps)
    org = await orgs.get_organization(org_id)
    if org is None:
        raise NotFoundError(f"Organization {org_id!r} does not exist")
    org = dict(org)
    org["members"] = await orgs.get_members(org_id)
    org["pending_invitations"] = await orgs.get_pending_invitations(org_id)
    return org


@admin_router.delete("/organizations/{org_id}")
async def delete_organization(
    org_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_org_admin),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Delete an organization."""
    orgs = _require_orgs(deps)
    if not await orgs.delete_organization(org_id):
        raise NotFoundError(f"Organization {org_id!r} does not exist")
    await _audit(
        deps,
        EventType.ORG_UPDATED,
        f"Organization deleted: {org_id}",
        actor_id=current_user["id"],
        target_id=org_id,
        target_type="organization",
        ip_address=_client_ip(request),
        severity="warning",
    )
    return {"message": "Organization deleted", "org_id": org_id}


@admin_router.get("/organizations/{org_id}/members")
async def list_org_members(
    org_id: str,
    current_user: Dict[str, Any] = Depends(require_org_admin),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """List the members of an organization."""
    orgs = _require_orgs(deps)
    members = await orgs.get_members(org_id)
    return {"org_id": org_id, "members": members, "total": len(members)}


@admin_router.post("/organizations/{org_id}/members", status_code=status.HTTP_201_CREATED)
async def add_org_member(
    org_id: str,
    body: MemberAddSchema,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_org_admin),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Add a member directly (plan member cap enforced)."""
    orgs = _require_orgs(deps)
    member = await orgs.add_member(
        org_id, body.user_id, body.role, added_by=current_user["id"]
    )
    await _audit(
        deps,
        EventType.MEMBER_ADDED,
        f"Member {body.user_id} added to organization {org_id}",
        actor_id=current_user["id"],
        target_id=org_id,
        target_type="organization",
        metadata={"member_user_id": body.user_id, "role": body.role},
        ip_address=_client_ip(request),
    )
    return member


@admin_router.patch("/organizations/{org_id}/members/{user_id}")
async def update_org_member_role(
    org_id: str,
    user_id: str,
    body: MemberRoleUpdateSchema,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_org_admin),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Change a member's role (last-owner demotion refused)."""
    orgs = _require_orgs(deps)
    member = await orgs.update_member_role(org_id, user_id, body.role)
    await _audit(
        deps,
        EventType.ROLE_CHANGED,
        f"Member {user_id} role changed to {body.role} in organization {org_id}",
        actor_id=current_user["id"],
        target_id=org_id,
        target_type="organization",
        metadata={"member_user_id": user_id, "role": body.role},
        ip_address=_client_ip(request),
    )
    return member


@admin_router.delete("/organizations/{org_id}/members/{user_id}")
async def remove_org_member(
    org_id: str,
    user_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_org_admin),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Remove a member (last-owner removal refused)."""
    orgs = _require_orgs(deps)
    if not await orgs.remove_member(org_id, user_id):
        raise NotFoundError(f"User {user_id!r} is not a member of {org_id!r}")
    await _audit(
        deps,
        EventType.MEMBER_REMOVED,
        f"Member {user_id} removed from organization {org_id}",
        actor_id=current_user["id"],
        target_id=org_id,
        target_type="organization",
        metadata={"member_user_id": user_id},
        ip_address=_client_ip(request),
        severity="warning",
    )
    return {"message": "Member removed", "org_id": org_id, "user_id": user_id}


@admin_router.post(
    "/organizations/{org_id}/invitations", status_code=status.HTTP_201_CREATED
)
async def create_org_invitation(
    org_id: str,
    body: InvitationCreateSchema,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_org_admin),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Invite an email to an organization.

    The invitation record (incl. its single-use token) is always returned;
    when no email service is configured the email itself is skipped and
    logged.
    """
    orgs = _require_orgs(deps)
    invitation = await orgs.send_invitation(
        org_id,
        body.email,
        body.role,
        invited_by=current_user["id"],
        expires_in_hours=body.expires_in_hours,
        message=body.message,
    )
    await _audit(
        deps,
        EventType.INVITATION_SENT,
        f"Invitation sent to {body.email} for organization {org_id}",
        actor_id=current_user["id"],
        target_id=org_id,
        target_type="organization",
        metadata={"email": body.email, "role": body.role},
        ip_address=_client_ip(request),
    )
    return invitation


@admin_router.get("/organizations/{org_id}/invitations")
async def list_org_invitations(
    org_id: str,
    current_user: Dict[str, Any] = Depends(require_org_admin),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Pending invitations for an organization."""
    orgs = _require_orgs(deps)
    invitations = await orgs.get_pending_invitations(org_id)
    return {"org_id": org_id, "invitations": invitations, "total": len(invitations)}


@admin_router.post("/invitations/accept")
async def accept_org_invitation(
    body: InvitationAcceptSchema,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Accept an invitation (single-use, expiry-checked).

    ``user_id`` defaults to the acting user — an admin may also accept on
    behalf of another user by passing it explicitly.
    """
    orgs = _require_orgs(deps)
    user_id = body.user_id or current_user["id"]
    member = await orgs.accept_invitation(body.token, user_id)
    await _audit(
        deps,
        EventType.INVITATION_ACCEPTED,
        f"Invitation accepted by user {user_id}",
        actor_id=current_user["id"],
        target_id=member.get("org_id"),
        target_type="organization",
        metadata={"member_user_id": user_id},
        ip_address=_client_ip(request),
    )
    return member


@admin_router.delete("/invitations/{token}")
async def decline_org_invitation(
    token: str,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Decline (delete) an invitation by token."""
    orgs = _require_orgs(deps)
    if not await orgs.decline_invitation(token):
        raise NotFoundError("Invitation not found")
    return {"message": "Invitation declined"}


# ---------------------------------------------------------------------------
# audit log
# ---------------------------------------------------------------------------

def _parse_event_types(event_types: Optional[str]) -> Optional[List[str]]:
    """Split a comma-separated event_types query param."""
    if not event_types:
        return None
    return [part.strip() for part in event_types.split(",") if part.strip()]


@admin_router.get("/audit-logs")
async def list_audit_logs(
    event_types: Optional[str] = Query(default=None),
    actor: Optional[str] = None,
    target: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Search the audit trail (delegates to db.search_audit_events)."""
    rows, total = await deps.db.search_audit_events(
        event_types=_parse_event_types(event_types),
        actor=actor,
        target=target,
        start=start,
        end=end,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    return {
        "events": rows,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size if total else 0,
        },
    }


@admin_router.get("/audit-logs/export")
async def export_audit_logs(
    format: str = Query(default="csv", pattern="^(csv|json)$"),
    event_types: Optional[str] = Query(default=None),
    actor: Optional[str] = None,
    target: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    limit: int = Query(default=10000, ge=1, le=50000),
    request: Request = None,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Response:
    """Export audit events; CSV output quotes ALL fields (QUOTE_ALL)."""
    if deps.audit_logger is None:
        audit: AuditLogger = AuditLogger(deps.db)
    else:
        audit = deps.audit_logger
    content = await audit.export_events(
        event_types=_parse_event_types(event_types),
        actor=actor,
        target=target,
        start=start,
        end=end,
        limit=limit,
        format=format,
    )
    await _audit(
        deps,
        EventType.DATA_EXPORT,
        f"Audit log export ({format})",
        actor_id=current_user["id"],
        metadata={"format": format, "limit": limit},
        ip_address=_client_ip(request),
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    media_type = "text/csv" if format == "csv" else "application/json"
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f"attachment; filename=audit_logs_{stamp}.{format}"
        },
    )


@admin_router.get("/audit-logs/{event_id}")
async def get_audit_event(
    event_id: str,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Fetch one audit event by id."""
    event = await deps.db.get_audit_event(event_id)
    if event is None:
        raise NotFoundError(f"Audit event {event_id!r} does not exist")
    return event


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------

@admin_router.get("/sessions")
async def list_sessions(
    user_id: str = Query(..., description="User whose active sessions to list"),
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Active sessions for one user (db contract: get_active_sessions)."""
    sessions = await deps.db.get_active_sessions(user_id)
    return {"user_id": user_id, "sessions": sessions, "total": len(sessions)}


@admin_router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Revoke a single session (atomic status flip)."""
    session = await deps.db.get_session(session_id)
    if session is None:
        raise NotFoundError(f"Session {session_id!r} does not exist")
    if not await deps.db.revoke_session(session_id):
        raise NotFoundError(f"Session {session_id!r} is not active")
    await _audit(
        deps,
        EventType.SESSION_REVOKED,
        f"Session revoked by admin: {session_id}",
        actor_id=current_user["id"],
        target_id=session_id,
        target_type="session",
        metadata={"user_id": session.get("user_id")},
        ip_address=_client_ip(request),
        severity="warning",
    )
    return {"message": "Session revoked", "session_id": session_id}


@admin_router.post("/sessions/user/{user_id}/revoke-all")
async def revoke_all_user_sessions(
    user_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Revoke every active session of a user."""
    count = await deps.db.revoke_all_user_sessions(user_id)
    await _audit(
        deps,
        EventType.SESSION_REVOKED,
        f"All sessions revoked for user {user_id} by admin",
        actor_id=current_user["id"],
        target_id=user_id,
        target_type="user",
        metadata={"sessions_revoked": count},
        ip_address=_client_ip(request),
        severity="warning",
    )
    return {"message": f"Revoked {count} session(s)", "revoked": count}


# ---------------------------------------------------------------------------
# webhooks
# ---------------------------------------------------------------------------

@admin_router.get("/webhooks")
async def list_webhooks(
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """List webhook endpoints (secrets masked)."""
    webhooks = _require_webhooks(deps)
    endpoints = await webhooks.list_endpoints()
    return {"webhooks": endpoints, "total": len(endpoints)}


@admin_router.post("/webhooks", status_code=status.HTTP_201_CREATED)
async def create_webhook(
    body: WebhookEndpointCreate,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Register a webhook endpoint (URL safety validated, §7).

    The signing secret is returned ONCE in this response.
    """
    webhooks = _require_webhooks(deps)
    endpoint = await webhooks.register_endpoint(
        body.url,
        body.events,
        description=body.description,
        enabled=body.enabled,
    )
    await _audit(
        deps,
        EventType.ADMIN_ACTION,
        f"Webhook endpoint registered: {body.url}",
        actor_id=current_user["id"],
        target_id=endpoint["id"],
        target_type="webhook_endpoint",
        ip_address=_client_ip(request),
    )
    return endpoint


@admin_router.get("/webhooks/{webhook_id}")
async def get_webhook(
    webhook_id: str,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Fetch one endpoint (secret masked)."""
    webhooks = _require_webhooks(deps)
    endpoint = await webhooks.get_endpoint(webhook_id)
    if endpoint is None:
        raise NotFoundError(f"Webhook endpoint {webhook_id!r} does not exist")
    return endpoint


@admin_router.put("/webhooks/{webhook_id}")
async def update_webhook(
    webhook_id: str,
    body: WebhookEndpointUpdate,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Update an endpoint (new URLs are re-validated)."""
    webhooks = _require_webhooks(deps)
    return await webhooks.update_endpoint(
        webhook_id,
        url=body.url,
        events=body.events,
        enabled=body.enabled,
        description=body.description,
    )


@admin_router.delete("/webhooks/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Delete an endpoint and its delivery history."""
    webhooks = _require_webhooks(deps)
    if not await webhooks.delete_endpoint(webhook_id):
        raise NotFoundError(f"Webhook endpoint {webhook_id!r} does not exist")
    return {"message": "Webhook endpoint deleted", "webhook_id": webhook_id}


@admin_router.post("/webhooks/{webhook_id}/rotate-secret")
async def rotate_webhook_secret(
    webhook_id: str,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Rotate an endpoint signing secret (new secret returned once)."""
    webhooks = _require_webhooks(deps)
    return await webhooks.rotate_endpoint_secret(webhook_id)


@admin_router.get("/webhooks/{webhook_id}/deliveries")
async def get_webhook_deliveries(
    webhook_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Recent delivery attempts for an endpoint."""
    webhooks = _require_webhooks(deps)
    deliveries = await webhooks.get_deliveries(webhook_id, limit=limit)
    return {"webhook_id": webhook_id, "deliveries": deliveries, "total": len(deliveries)}


@admin_router.post("/webhooks/{webhook_id}/test")
async def test_webhook(
    webhook_id: str,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Send a signed test delivery immediately."""
    webhooks = _require_webhooks(deps)
    return await webhooks.send_test_event(webhook_id)


# ---------------------------------------------------------------------------
# health + dashboard metrics
# ---------------------------------------------------------------------------

@admin_router.get("/health")
async def get_system_health(
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """System health via db.health_check() + cache.health_check()."""
    components: Dict[str, str] = {}
    healthy = True
    try:
        db_ok = await deps.db.health_check()
        components["database"] = "healthy" if db_ok else "unhealthy"
        healthy = healthy and db_ok
    except Exception:  # noqa: BLE001 - health endpoints never raise
        components["database"] = "unhealthy"
        healthy = False
    try:
        cache_ok = await deps.cache.health_check()
        components["cache"] = "healthy" if cache_ok else "unhealthy"
        healthy = healthy and cache_ok
    except Exception:  # noqa: BLE001
        components["cache"] = "unhealthy"
        healthy = False
    return {
        "status": "healthy" if healthy else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": components,
    }


@admin_router.get("/dashboard/metrics")
async def get_dashboard_metrics(
    days: int = Query(default=7, ge=1, le=90),
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Real dashboard metrics computed from the db/audit contract."""
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=days)

    total_users = await deps.db.count_users()
    mfa_users = await deps.db.count_users(mfa_enabled=True)
    new_users_7d = await deps.db.count_users(created_since=now - timedelta(days=7))
    _orgs_rows, total_orgs = await deps.db.list_organizations(limit=1, offset=0)

    stats = await deps.db.get_audit_statistics(since=window_start)
    by_type = stats.get("events_by_type", {})
    login_success = by_type.get(EventType.LOGIN_SUCCESS.value, 0)
    login_failed = by_type.get(EventType.LOGIN_FAILED.value, 0)
    login_total = login_success + login_failed

    # Distinct actors with successful logins in the last 24h.
    day_rows, _day_total = await deps.db.search_audit_events(
        event_types=[EventType.LOGIN_SUCCESS.value],
        start=now - timedelta(hours=24),
        limit=1000,
    )
    active_users_24h = len({row.get("actor") for row in day_rows if row.get("actor")})

    security_rows, security_total = await deps.db.search_audit_events(
        event_types=[
            EventType.LOGIN_FAILED.value,
            EventType.ACCOUNT_LOCKED.value,
            EventType.RATE_LIMIT_EXCEEDED.value,
            EventType.SUSPICIOUS_ACTIVITY.value,
            EventType.MFA_CODE_FAILED.value,
        ],
        start=now - timedelta(hours=24),
        limit=1,
    )

    # Active sessions across users (bounded scan, db contract only).
    user_rows, _user_total = await deps.db.list_users(limit=10000, offset=0)
    active_sessions = 0
    for user in user_rows:
        active_sessions += len(await deps.db.get_active_sessions(user["id"]))

    # Webhook delivery success rate from recorded deliveries.
    deliveries_total = 0
    deliveries_success = 0
    if deps.webhooks is not None:
        for endpoint in await deps.db.list_webhook_endpoints():
            for delivery in await deps.db.get_webhook_deliveries(
                endpoint["id"], limit=200
            ):
                deliveries_total += 1
                if delivery.get("status") == "success":
                    deliveries_success += 1

    return {
        "total_users": total_users,
        "active_users_24h": active_users_24h,
        "new_users_7d": new_users_7d,
        "total_organizations": total_orgs,
        "active_sessions": active_sessions,
        "login_success_rate": round(login_success / login_total * 100, 2)
        if login_total
        else 0.0,
        "mfa_adoption_rate": round(mfa_users / total_users * 100, 2)
        if total_users
        else 0.0,
        "security_events_24h": security_total,
        "webhook_delivery_rate": round(
            deliveries_success / deliveries_total * 100, 2
        )
        if deliveries_total
        else 0.0,
        "window_days": days,
    }


@admin_router.get("/dashboard/chart-data")
async def get_chart_data(
    metric: str = Query(default="all"),
    days: int = Query(default=30, ge=1, le=365),
    granularity: str = Query(default="day", pattern="^(hour|day|week)$"),
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Time-series audit counts bucketed by granularity."""
    bucket_seconds = {"hour": 3600, "day": 86400, "week": 7 * 86400}[granularity]
    since = datetime.now(timezone.utc) - timedelta(days=days)
    buckets = await deps.db.get_audit_time_series(
        since=since, bucket_seconds=bucket_seconds
    )
    event_types = None if metric == "all" else [metric]
    if event_types is not None:
        # Re-bucket from filtered events (contract has no type-filtered series).
        rows, _total = await deps.db.search_audit_events(
            event_types=event_types, start=since, limit=10000
        )
        counts: Dict[int, int] = {}
        for row in rows:
            ts = row.get("timestamp")
            if ts is None:
                continue
            index = int((ts - since).total_seconds() // bucket_seconds)
            counts[index] = counts.get(index, 0) + 1
        for bucket_index, bucket in enumerate(buckets):
            bucket["count"] = counts.get(bucket_index, 0)
    return {
        "metric": metric,
        "granularity": granularity,
        "data": [
            {
                "label": bucket["bucket_start"].isoformat()
                if isinstance(bucket.get("bucket_start"), datetime)
                else str(bucket.get("bucket_start")),
                "timestamp": bucket["bucket_start"].isoformat()
                if isinstance(bucket.get("bucket_start"), datetime)
                else str(bucket.get("bucket_start")),
                "value": bucket.get("count", 0),
            }
            for bucket in buckets
        ],
    }


# ---------------------------------------------------------------------------
# app wiring
# ---------------------------------------------------------------------------

def install_admin_api(app: Any, deps: AdminDependencies) -> Any:
    """Wire the admin surface onto an existing FastAPI app (§5).

    - registers ``deps`` on ``app.state.admin_deps``;
    - installs TesseraError/ValueError/PermissionError handlers (§1);
    - includes the v1 dashboard router, the v2 enterprise router and the
      RBAC router.
    """
    from tessera.admin.dashboard_enterprise import enterprise_router
    from tessera.admin.rbac_api import rbac_router

    app.state.admin_deps = deps
    register_error_handlers(app)
    app.include_router(admin_router)
    app.include_router(enterprise_router)
    app.include_router(rbac_router)
    return app


def create_admin_app(deps: AdminDependencies) -> Any:
    """Build a standalone FastAPI app with the full admin surface."""
    from contextlib import asynccontextmanager

    from fastapi import FastAPI

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if deps.audit_logger is not None:
            deps.audit_logger.start()
        yield
        if deps.audit_logger is not None:
            await deps.audit_logger.close()

    app = FastAPI(
        title="Tessera Admin API",
        version="2.0.0",
        lifespan=lifespan,
    )
    return install_admin_api(app, deps)
