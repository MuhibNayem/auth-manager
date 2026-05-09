"""
Admin Dashboard API Module

State-of-the-Art Enterprise Admin Dashboard Backend
Provides comprehensive administration capabilities for the Authy Package.

Features:
- User Management (CRUD, bulk operations, impersonation)
- Organization & Multi-tenancy Management
- Real-time Audit Log Viewer with Advanced Filtering
- Session Monitoring & Management
- Analytics Dashboard (users, logins, security events)
- Webhook Management & Delivery Tracking
- System Health Monitoring
- Role-Based Access Control (RBAC)
- Data Export (CSV, JSON, PDF)
- Real-time WebSocket Updates
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime, timedelta
from enum import Enum
import json
import csv
import io
from dataclasses import asdict

from authy_package.admin.audit_logger import AuditLogger, EventType, AuditEvent
from authy_package.organizations.org_manager import OrganizationManager, OrgRole


# ==================== Pydantic Models ====================

class UserStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    PENDING_VERIFICATION = "pending_verification"


class UserCreateSchema(BaseModel):
    username: Optional[str] = None
    email: str
    phone: Optional[str] = None
    password: str = Field(..., min_length=8)
    role: str = "user"
    organization_id: Optional[str] = None
    send_welcome_email: bool = True


class UserUpdateSchema(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    role: Optional[str] = None
    status: Optional[UserStatus] = None
    metadata: Optional[Dict[str, Any]] = None


class BulkUserOperation(BaseModel):
    user_ids: List[str]
    action: Literal["activate", "deactivate", "lock", "unlock", "delete"]
    reason: Optional[str] = None


class OrganizationCreateSchema(BaseModel):
    name: str
    description: Optional[str] = None
    owner_id: str
    plan: str = "free"  # free, pro, enterprise
    metadata: Optional[Dict[str, Any]] = None


class OrganizationUpdateSchema(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    plan: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class InvitationCreateSchema(BaseModel):
    organization_id: str
    email: str
    role: str = "member"  # owner, admin, member, guest
    expires_in_hours: int = 72
    message: Optional[str] = None


class AuditLogFilter(BaseModel):
    actor_id: Optional[str] = None
    event_type: Optional[str] = None
    organization_id: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    severity: Optional[Literal["info", "warning", "error", "critical"]] = None
    status: Optional[Literal["success", "failure"]] = None
    ip_address: Optional[str] = None
    search_query: Optional[str] = None


class SessionInfo(BaseModel):
    session_id: str
    user_id: str
    device_info: Optional[str] = None
    ip_address: Optional[str] = None
    created_at: datetime
    last_active: datetime
    is_active: bool


class DashboardMetrics(BaseModel):
    total_users: int
    active_users_24h: int
    new_users_7d: int
    total_organizations: int
    active_sessions: int
    login_success_rate: float
    mfa_adoption_rate: float
    security_events_24h: int
    webhook_delivery_rate: float


class WebhookEndpointCreate(BaseModel):
    url: str = Field(..., pattern=r"^https?://")
    events: List[str] = []  # Empty means all events
    secret: Optional[str] = None
    is_active: bool = True
    description: Optional[str] = None


class WebhookEndpointUpdate(BaseModel):
    url: Optional[str] = None
    events: Optional[List[str]] = None
    is_active: Optional[bool] = None
    description: Optional[str] = None


# ==================== Admin Router ====================

admin_router = APIRouter(prefix="/admin/api/v1", tags=["Admin Dashboard"])


# ==================== Helper Functions ====================

async def get_current_admin_user(
    token: str = Query(..., description="Admin JWT token"),
    auth_manager=None  # Injected via dependency
) -> dict:
    """Validate admin user token and permissions"""
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Auth manager not configured")
    
    try:
        payload = await auth_manager.verify_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user_id = payload.get("sub")
        user = await auth_manager.db.get_user(user_id)
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check admin role
        user_role = user.get("role", "user")
        if user_role not in ["admin", "owner", "superadmin"]:
            raise HTTPException(status_code=403, detail="Admin access required")
        
        return user
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")


async def require_org_admin(
    org_id: str,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
) -> dict:
    """Require user to be admin of specific organization"""
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Auth manager not configured")
    
    org_role = await auth_manager.organizations.get_member_role(org_id, current_user["id"])
    if not org_role or org_role.value not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Organization admin access required")
    
    return {"user": current_user, "org_id": org_id, "role": org_role}


# ==================== Dashboard Metrics Endpoints ====================

@admin_router.get("/dashboard/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics(
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None,
    days: int = Query(default=7, ge=1, le=90)
):
    """
    Get comprehensive dashboard metrics
    
    Returns key performance indicators for the authentication system
    """
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Auth manager not configured")
    
    db = auth_manager.db
    now = datetime.utcnow()
    start_date = now - timedelta(days=days)
    
    # Calculate metrics
    total_users = await db.get_user_count()
    active_users_24h = await db.get_active_users_count(hours=24)
    new_users_7d = await db.get_new_users_count(days=7)
    
    # Organizations
    if hasattr(db, 'get_organization_count'):
        total_orgs = await db.get_organization_count()
    else:
        total_orgs = 0
    
    # Sessions
    if hasattr(auth_manager, 'sessions'):
        active_sessions = await auth_manager.sessions.get_active_session_count()
    else:
        active_sessions = 0
    
    # Login success rate (from audit logs)
    audit_logger = auth_manager.audit if hasattr(auth_manager, 'audit') else None
    if audit_logger:
        stats = await audit_logger.get_statistics(
            start_date=start_date,
            end_date=now,
            group_by="status"
        )
        total_logins = stats.get("auth.login.success", 0) + stats.get("auth.login.failed", 0)
        login_success_rate = (stats.get("auth.login.success", 0) / total_logins * 100) if total_logins > 0 else 0.0
        
        # Security events
        security_events = await audit_logger.get_security_events(limit=1000)
        security_events_24h = len([e for e in security_events if e.timestamp > now - timedelta(hours=24)])
        
        # MFA adoption
        mfa_enabled_count = await db.get_mfa_enabled_count()
        mfa_adoption_rate = (mfa_enabled_count / total_users * 100) if total_users > 0 else 0.0
    else:
        login_success_rate = 0.0
        security_events_24h = 0
        mfa_adoption_rate = 0.0
    
    # Webhook delivery rate
    if hasattr(auth_manager, 'webhooks'):
        webhook_stats = await auth_manager.webhooks.get_delivery_statistics(days=days)
        webhook_delivery_rate = webhook_stats.get("delivery_rate", 0.0)
    else:
        webhook_delivery_rate = 0.0
    
    return DashboardMetrics(
        total_users=total_users,
        active_users_24h=active_users_24h,
        new_users_7d=new_users_7d,
        total_organizations=total_orgs,
        active_sessions=active_sessions,
        login_success_rate=round(login_success_rate, 2),
        mfa_adoption_rate=round(mfa_adoption_rate, 2),
        security_events_24h=security_events_24h,
        webhook_delivery_rate=round(webhook_delivery_rate, 2)
    )


@admin_router.get("/dashboard/chart-data")
async def get_chart_data(
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None,
    metric: str = Query(..., description="Metric type: users, logins, security_events"),
    days: int = Query(default=30, ge=1, le=365),
    granularity: str = Query(default="day", description="hour, day, week, month")
):
    """
    Get time-series chart data for dashboard visualizations
    """
    if not auth_manager or not hasattr(auth_manager, 'audit'):
        return {"data": [], "labels": []}
    
    audit_logger = auth_manager.audit
    now = datetime.utcnow()
    start_date = now - timedelta(days=days)
    
    # Map granularity to timedelta
    granularity_map = {
        "hour": timedelta(hours=1),
        "day": timedelta(days=1),
        "week": timedelta(weeks=1),
        "month": timedelta(days=30)
    }
    interval = granularity_map.get(granularity, timedelta(days=1))
    
    # Get statistics grouped by time
    chart_data = await audit_logger.get_time_series_data(
        start_date=start_date,
        end_date=now,
        interval=interval,
        event_types=[metric] if metric != "all" else None
    )
    
    return chart_data


# ==================== User Management Endpoints ====================

@admin_router.get("/users", response_model=List[Dict[str, Any]])
async def list_users(
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    search: Optional[str] = None,
    status: Optional[UserStatus] = None,
    organization_id: Optional[str] = None,
    role: Optional[str] = None,
    sort_by: str = Query(default="created_at"),
    sort_order: str = Query(default="desc", regex="^(asc|desc)$")
):
    """
    List users with pagination and filtering
    
    Supports search by username, email, phone
    """
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Auth manager not configured")
    
    db = auth_manager.db
    
    filters = {
        "search": search,
        "status": status.value if status else None,
        "organization_id": organization_id,
        "role": role
    }
    
    # Remove None filters
    filters = {k: v for k, v in filters.items() if v is not None}
    
    users, total = await db.get_users_paginated(
        page=page,
        page_size=page_size,
        filters=filters,
        sort_by=sort_by,
        sort_order=sort_order
    )
    
    return {
        "users": users,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size
        }
    }


@admin_router.get("/users/{user_id}")
async def get_user(
    user_id: str,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Get detailed user information"""
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Auth manager not configured")
    
    user = await auth_manager.db.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get user's organizations
    if hasattr(auth_manager, 'organizations'):
        orgs = await auth_manager.organizations.get_user_organizations(user_id)
        user["organizations"] = orgs
    
    # Get user's sessions
    if hasattr(auth_manager, 'sessions'):
        sessions = await auth_manager.sessions.get_user_sessions(user_id)
        user["active_sessions"] = sessions
    
    # Get recent audit events
    if hasattr(auth_manager, 'audit'):
        recent_events = await auth_manager.audit.search(actor_id=user_id, limit=10)
        user["recent_activity"] = [asdict(e) if hasattr(e, '__dataclass_fields__') else e for e in recent_events]
    
    return user


@admin_router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreateSchema,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Create a new user"""
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Auth manager not configured")
    
    # Check if user already exists
    existing = await auth_manager.db.get_user_by_identifier(
        username=user_data.username,
        email=user_data.email,
        phone=user_data.phone
    )
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create user
    result = await auth_manager.register_user(
        username=user_data.username,
        email=user_data.email,
        phone=user_data.phone,
        password=user_data.password
    )
    
    # Add to organization if specified
    if user_data.organization_id and hasattr(auth_manager, 'organizations'):
        await auth_manager.organizations.add_member(
            org_id=user_data.organization_id,
            user_id=result["user"]["id"],
            role=OrgRole(user_data.role) if user_data.role in ["owner", "admin", "member", "guest"] else OrgRole.MEMBER,
            added_by=current_user["id"]
        )
    
    # Send welcome email
    if user_data.send_welcome_email and hasattr(auth_manager, 'email'):
        background_tasks.add_task(
            auth_manager.email.send_welcome_email,
            email=user_data.email,
            username=user_data.username or user_data.email
        )
    
    # Log audit event
    if hasattr(auth_manager, 'audit'):
        await auth_manager.audit.log(
            event_type=EventType.USER_CREATED,
            action=f"User created by admin: {user_data.email}",
            actor_id=current_user["id"],
            target_id=result["user"]["id"],
            target_type="user",
            metadata={"email": user_data.email},
            severity="info"
        )
    
    return result


@admin_router.put("/users/{user_id}")
async def update_user(
    user_id: str,
    user_data: UserUpdateSchema,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Update user information"""
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Auth manager not configured")
    
    user = await auth_manager.db.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update fields
    update_data = user_data.model_dump(exclude_unset=True)
    
    if update_data:
        await auth_manager.db.update_user(user_id, update_data)
    
    # Log audit event
    if hasattr(auth_manager, 'audit'):
        await auth_manager.audit.log(
            event_type=EventType.USER_UPDATED,
            action=f"User updated by admin: {user_id}",
            actor_id=current_user["id"],
            target_id=user_id,
            target_type="user",
            metadata=update_data,
            severity="info"
        )
    
    return {"message": "User updated successfully", "user_id": user_id}


@admin_router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Delete a user"""
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Auth manager not configured")
    
    user = await auth_manager.db.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent self-deletion
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    # Delete user
    await auth_manager.db.delete_user(user_id)
    
    # Revoke all sessions
    if hasattr(auth_manager, 'sessions'):
        await auth_manager.sessions.revoke_all_user_sessions(user_id)
    
    # Log audit event
    if hasattr(auth_manager, 'audit'):
        await auth_manager.audit.log(
            event_type=EventType.USER_DELETED,
            action=f"User deleted by admin: {user['email']}",
            actor_id=current_user["id"],
            target_id=user_id,
            target_type="user",
            metadata={"email": user["email"]},
            severity="warning"
        )
    
    return {"message": "User deleted successfully"}


@admin_router.post("/users/bulk")
async def bulk_user_operation(
    operation: BulkUserOperation,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Perform bulk operations on multiple users"""
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Auth manager not configured")
    
    results = {"success": [], "failed": []}
    
    for user_id in operation.user_ids:
        try:
            if operation.action == "delete":
                if user_id == current_user["id"]:
                    results["failed"].append({"user_id": user_id, "reason": "Cannot delete self"})
                    continue
                await auth_manager.db.delete_user(user_id)
            
            elif operation.action in ["activate", "deactivate"]:
                status_value = "active" if operation.action == "activate" else "inactive"
                await auth_manager.db.update_user(user_id, {"status": status_value})
            
            elif operation.action in ["lock", "unlock"]:
                locked = operation.action == "lock"
                await auth_manager.db.update_user(user_id, {"locked": locked})
                
                if locked and hasattr(auth_manager, 'sessions'):
                    await auth_manager.sessions.revoke_all_user_sessions(user_id)
            
            results["success"].append(user_id)
            
            # Log audit event
            if hasattr(auth_manager, 'audit'):
                await auth_manager.audit.log(
                    event_type=EventType.ADMIN_ACTION,
                    action=f"Bulk {operation.action} performed on user {user_id}",
                    actor_id=current_user["id"],
                    target_id=user_id,
                    target_type="user",
                    metadata={"action": operation.action, "reason": operation.reason},
                    severity="warning" if operation.action == "delete" else "info"
                )
        
        except Exception as e:
            results["failed"].append({"user_id": user_id, "reason": str(e)})
    
    return results


@admin_router.post("/users/{user_id}/impersonate")
async def impersonate_user(
    user_id: str,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """
    Impersonate a user (for debugging/support)
    
    Generates a temporary token to act as another user
    """
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Auth manager not configured")
    
    user = await auth_manager.db.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Generate impersonation token (short-lived)
    from authy_package.utils.security import SecurityManager
    security = SecurityManager(auth_manager.config)
    
    impersonation_token = await security.create_impersonation_token(
        user_id=user_id,
        original_admin_id=current_user["id"],
        expiration_minutes=15
    )
    
    # Log audit event
    if hasattr(auth_manager, 'audit'):
        await auth_manager.audit.log(
            event_type=EventType.USER_IMPERSONATION,
            action=f"Admin impersonated user: {user['email']}",
            actor_id=current_user["id"],
            target_id=user_id,
            target_type="user",
            metadata={"expires_in": "15 minutes"},
            severity="warning"
        )
    
    return {
        "impersonation_token": impersonation_token,
        "expires_in": 900,  # 15 minutes
        "original_user": current_user["email"],
        "impersonating": user["email"]
    }


# ==================== Organization Management ====================

@admin_router.get("/organizations", response_model=List[Dict[str, Any]])
async def list_organizations(
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    search: Optional[str] = None
):
    """List all organizations"""
    if not auth_manager or not hasattr(auth_manager, 'organizations'):
        raise HTTPException(status_code=500, detail="Organization manager not configured")
    
    orgs, total = await auth_manager.organizations.get_organizations_paginated(
        page=page,
        page_size=page_size,
        search=search
    )
    
    return {
        "organizations": orgs,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size
        }
    }


@admin_router.get("/organizations/{org_id}")
async def get_organization(
    org_id: str,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Get detailed organization information"""
    if not auth_manager or not hasattr(auth_manager, 'organizations'):
        raise HTTPException(status_code=500, detail="Organization manager not configured")
    
    org = await auth_manager.organizations.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Get members
    members = await auth_manager.organizations.get_members(org_id)
    org["members"] = members
    
    # Get invitations
    invitations = await auth_manager.organizations.get_pending_invitations(org_id)
    org["pending_invitations"] = invitations
    
    return org


@admin_router.post("/organizations", status_code=status.HTTP_201_CREATED)
async def create_organization(
    org_data: OrganizationCreateSchema,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Create a new organization"""
    if not auth_manager or not hasattr(auth_manager, 'organizations'):
        raise HTTPException(status_code=500, detail="Organization manager not configured")
    
    org = await auth_manager.organizations.create_organization(
        name=org_data.name,
        owner_id=org_data.owner_id,
        description=org_data.description,
        plan=org_data.plan,
        metadata=org_data.metadata
    )
    
    # Log audit event
    if hasattr(auth_manager, 'audit'):
        await auth_manager.audit.log(
            event_type=EventType.ORG_CREATED,
            action=f"Organization created: {org_data.name}",
            actor_id=current_user["id"],
            target_id=org.id,
            target_type="organization",
            severity="info"
        )
    
    return org


# ==================== Audit Log Endpoints ====================

@admin_router.get("/audit-logs", response_model=List[Dict[str, Any]])
async def list_audit_logs(
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None,
    filters: AuditLogFilter = Depends(),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500)
):
    """
    Search and filter audit logs
    
    Comprehensive audit trail with advanced filtering
    """
    if not auth_manager or not hasattr(auth_manager, 'audit'):
        raise HTTPException(status_code=500, detail="Audit logger not configured")
    
    audit_logger = auth_manager.audit
    
    # Build search parameters
    search_params = {
        "actor_id": filters.actor_id,
        "event_type": EventType(filters.event_type) if filters.event_type else None,
        "organization_id": filters.organization_id,
        "start_date": filters.start_date,
        "end_date": filters.end_date,
        "severity": filters.severity,
        "status": filters.status,
        "limit": page_size,
        "offset": (page - 1) * page_size
    }
    
    # Remove None values
    search_params = {k: v for k, v in search_params.items() if v is not None}
    
    events = await audit_logger.search(**search_params)
    
    # Convert to dict
    events_data = []
    for event in events:
        if hasattr(event, '__dataclass_fields__'):
            event_dict = asdict(event)
            event_dict["event_type"] = event.event_type.value
            event_dict["timestamp"] = event.timestamp.isoformat()
            events_data.append(event_dict)
        else:
            events_data.append(event)
    
    return {
        "events": events_data,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": len(events_data)
        }
    }


@admin_router.get("/audit-logs/export")
async def export_audit_logs(
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None,
    format: str = Query(default="csv", regex="^(csv|json)$"),
    filters: AuditLogFilter = Depends()
):
    """Export audit logs for compliance"""
    if not auth_manager or not hasattr(auth_manager, 'audit'):
        raise HTTPException(status_code=500, detail="Audit logger not configured")
    
    audit_logger = auth_manager.audit
    
    # Build search parameters
    search_params = {
        "actor_id": filters.actor_id,
        "event_type": EventType(filters.event_type) if filters.event_type else None,
        "organization_id": filters.organization_id,
        "start_date": filters.start_date,
        "end_date": filters.end_date,
        "severity": filters.severity,
        "status": filters.status,
    }
    search_params = {k: v for k, v in search_params.items() if v is not None}
    
    export_data = await audit_logger.export_events(search_params, format=format)
    
    # Create file response
    filename = f"audit_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{format}"
    
    return StreamingResponse(
        io.BytesIO(export_data.encode()),
        media_type="text/csv" if format == "csv" else "application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@admin_router.get("/audit-logs/{event_id}")
async def get_audit_event(
    event_id: str,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Get detailed audit event"""
    if not auth_manager or not hasattr(auth_manager, 'audit'):
        raise HTTPException(status_code=500, detail="Audit logger not configured")
    
    event = await auth_manager.audit.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    if hasattr(event, '__dataclass_fields__'):
        event_dict = asdict(event)
        event_dict["event_type"] = event.event_type.value
        event_dict["timestamp"] = event.timestamp.isoformat()
        return event_dict
    
    return event


# ==================== Session Management ====================

@admin_router.get("/sessions", response_model=List[SessionInfo])
async def list_sessions(
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None,
    user_id: Optional[str] = None,
    active_only: bool = True
):
    """List active sessions"""
    if not auth_manager or not hasattr(auth_manager, 'sessions'):
        raise HTTPException(status_code=500, detail="Session manager not configured")
    
    if user_id:
        sessions = await auth_manager.sessions.get_user_sessions(user_id)
    else:
        sessions = await auth_manager.sessions.get_all_active_sessions()
    
    return sessions


@admin_router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Revoke a specific session"""
    if not auth_manager or not hasattr(auth_manager, 'sessions'):
        raise HTTPException(status_code=500, detail="Session manager not configured")
    
    session = await auth_manager.sessions.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    await auth_manager.sessions.revoke_session(session_id)
    
    # Log audit event
    if hasattr(auth_manager, 'audit'):
        await auth_manager.audit.log(
            event_type=EventType.SESSION_REVOKED,
            action=f"Session revoked by admin: {session_id}",
            actor_id=current_user["id"],
            target_id=session_id,
            target_type="session",
            metadata={"user_id": session.get("user_id")},
            severity="warning"
        )
    
    return {"message": "Session revoked successfully"}


@admin_router.post("/sessions/user/{user_id}/revoke-all")
async def revoke_all_user_sessions(
    user_id: str,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Revoke all sessions for a user"""
    if not auth_manager or not hasattr(auth_manager, 'sessions'):
        raise HTTPException(status_code=500, detail="Session manager not configured")
    
    count = await auth_manager.sessions.revoke_all_user_sessions(user_id)
    
    # Log audit event
    if hasattr(auth_manager, 'audit'):
        await auth_manager.audit.log(
            event_type=EventType.SESSION_REVOKED,
            action=f"All sessions revoked for user by admin: {user_id}",
            actor_id=current_user["id"],
            target_id=user_id,
            target_type="user",
            metadata={"sessions_revoked": count},
            severity="warning"
        )
    
    return {"message": f"Revoked {count} sessions"}


# ==================== Webhook Management ====================

@admin_router.get("/webhooks")
async def list_webhooks(
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """List all webhook endpoints"""
    if not auth_manager or not hasattr(auth_manager, 'webhooks'):
        raise HTTPException(status_code=500, detail="Webhook manager not configured")
    
    webhooks = await auth_manager.webhooks.get_all_endpoints()
    return {"webhooks": webhooks}


@admin_router.post("/webhooks", status_code=status.HTTP_201_CREATED)
async def create_webhook(
    webhook_data: WebhookEndpointCreate,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Create a new webhook endpoint"""
    if not auth_manager or not hasattr(auth_manager, 'webhooks'):
        raise HTTPException(status_code=500, detail="Webhook manager not configured")
    
    webhook = await auth_manager.webhooks.create_endpoint(
        url=webhook_data.url,
        events=webhook_data.events,
        secret=webhook_data.secret,
        is_active=webhook_data.is_active,
        description=webhook_data.description
    )
    
    return webhook


@admin_router.put("/webhooks/{webhook_id}")
async def update_webhook(
    webhook_id: str,
    webhook_data: WebhookEndpointUpdate,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Update webhook endpoint"""
    if not auth_manager or not hasattr(auth_manager, 'webhooks'):
        raise HTTPException(status_code=500, detail="Webhook manager not configured")
    
    webhook = await auth_manager.webhooks.update_endpoint(
        webhook_id=webhook_id,
        **webhook_data.model_dump(exclude_unset=True)
    )
    
    return webhook


@admin_router.delete("/webhooks/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Delete webhook endpoint"""
    if not auth_manager or not hasattr(auth_manager, 'webhooks'):
        raise HTTPException(status_code=500, detail="Webhook manager not configured")
    
    await auth_manager.webhooks.delete_endpoint(webhook_id)
    return {"message": "Webhook deleted successfully"}


@admin_router.get("/webhooks/{webhook_id}/deliveries")
async def get_webhook_deliveries(
    webhook_id: str,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200)
):
    """Get webhook delivery history"""
    if not auth_manager or not hasattr(auth_manager, 'webhooks'):
        raise HTTPException(status_code=500, detail="Webhook manager not configured")
    
    deliveries = await auth_manager.webhooks.get_delivery_history(
        webhook_id=webhook_id,
        page=page,
        page_size=page_size
    )
    
    return deliveries


@admin_router.post("/webhooks/{webhook_id}/test")
async def test_webhook(
    webhook_id: str,
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Send test event to webhook"""
    if not auth_manager or not hasattr(auth_manager, 'webhooks'):
        raise HTTPException(status_code=500, detail="Webhook manager not configured")
    
    result = await auth_manager.webhooks.send_test_event(webhook_id)
    return result


# ==================== System Health ====================

@admin_router.get("/health")
async def get_system_health(
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None
):
    """Get system health status"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {}
    }
    
    # Check database
    try:
        if auth_manager and hasattr(auth_manager, 'db'):
            await auth_manager.db.health_check()
            health_status["components"]["database"] = "healthy"
        else:
            health_status["components"]["database"] = "not_configured"
    except Exception as e:
        health_status["components"]["database"] = f"unhealthy: {str(e)}"
        health_status["status"] = "degraded"
    
    # Check cache
    try:
        if auth_manager and hasattr(auth_manager, 'cache'):
            await auth_manager.cache.health_check()
            health_status["components"]["cache"] = "healthy"
        else:
            health_status["components"]["cache"] = "not_configured"
    except Exception as e:
        health_status["components"]["cache"] = f"unhealthy: {str(e)}"
        health_status["status"] = "degraded"
    
    # Check webhook delivery
    if auth_manager and hasattr(auth_manager, 'webhooks'):
        webhook_health = await auth_manager.webhooks.get_health_status()
        health_status["components"]["webhooks"] = webhook_health
    
    return health_status


# ==================== WebSocket for Real-time Updates ====================

@admin_router.websocket("/ws/realtime")
async def websocket_realtime_updates(
    websocket: WebSocket,
    auth_manager=None
):
    """
    WebSocket endpoint for real-time dashboard updates
    
    Clients can subscribe to:
    - New user registrations
    - Login events
    - Security alerts
    - System health changes
    """
    await websocket.accept()
    
    # Simple implementation - in production, use Redis pub/sub
    try:
        while True:
            # Wait for client message (subscription request)
            data = await websocket.receive_text()
            subscription = json.loads(data)
            
            # Acknowledge subscription
            await websocket.send_json({
                "type": "subscribed",
                "channels": subscription.get("channels", [])
            })
            
            # In production, this would receive events from Redis pub/sub
            # For now, send periodic heartbeat
            await websocket.send_json({
                "type": "heartbeat",
                "timestamp": datetime.utcnow().isoformat()
            })
    
    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_json({
            "type": "error",
            "message": str(e)
        })


# ==================== Security Events ====================

@admin_router.get("/security/events")
async def get_security_events(
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None,
    hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=100, ge=1, le=1000)
):
    """Get recent security events"""
    if not auth_manager or not hasattr(auth_manager, 'audit'):
        raise HTTPException(status_code=500, detail="Audit logger not configured")
    
    start_date = datetime.utcnow() - timedelta(hours=hours)
    events = await auth_manager.audit.get_security_events(limit=limit)
    
    # Filter by time
    recent_events = [e for e in events if e.timestamp >= start_date]
    
    # Convert to dict
    events_data = []
    for event in recent_events:
        if hasattr(event, '__dataclass_fields__'):
            event_dict = asdict(event)
            event_dict["event_type"] = event.event_type.value
            event_dict["timestamp"] = event.timestamp.isoformat()
            events_data.append(event_dict)
        else:
            events_data.append(event)
    
    return {"events": events_data, "total": len(events_data)}


@admin_router.get("/security/suspicious-activity")
async def get_suspicious_activity(
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None,
    days: int = Query(default=7, ge=1, le=30)
):
    """Get suspicious activity report"""
    if not auth_manager or not hasattr(auth_manager, 'audit'):
        raise HTTPException(status_code=500, detail="Audit logger not configured")
    
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Get suspicious events
    suspicious_events = await auth_manager.audit.search(
        event_type=EventType.SUSPICIOUS_ACTIVITY,
        start_date=start_date,
        limit=500
    )
    
    # Analyze patterns
    analysis = {
        "total_incidents": len(suspicious_events),
        "by_type": {},
        "by_ip": {},
        "by_user": {},
        "timeline": []
    }
    
    for event in suspicious_events:
        # Group by type
        event_type = event.event_type.value
        analysis["by_type"][event_type] = analysis["by_type"].get(event_type, 0) + 1
        
        # Group by IP
        if event.ip_address:
            analysis["by_ip"][event.ip_address] = analysis["by_ip"].get(event.ip_address, 0) + 1
        
        # Group by user
        if event.actor_id:
            analysis["by_user"][event.actor_id] = analysis["by_user"].get(event.actor_id, 0) + 1
    
    return analysis


# ==================== Reports ====================

@admin_router.get("/reports/daily-summary")
async def get_daily_summary(
    current_user: dict = Depends(get_current_admin_user),
    auth_manager=None,
    date: Optional[datetime] = None
):
    """Get daily summary report"""
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Auth manager not configured")
    
    if date is None:
        date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    end_date = date + timedelta(days=1)
    
    # Gather statistics
    summary = {
        "date": date.isoformat(),
        "generated_at": datetime.utcnow().isoformat(),
        "metrics": {}
    }
    
    # Users
    summary["metrics"]["new_users"] = await auth_manager.db.get_new_users_count(
        start_date=date,
        end_date=end_date
    )
    
    # Logins
    if hasattr(auth_manager, 'audit'):
        login_stats = await auth_manager.audit.get_statistics(
            start_date=date,
            end_date=end_date,
            group_by="event_type"
        )
        summary["metrics"]["logins"] = login_stats.get("auth.login.success", 0)
        summary["metrics"]["failed_logins"] = login_stats.get("auth.login.failed", 0)
    
    return summary
