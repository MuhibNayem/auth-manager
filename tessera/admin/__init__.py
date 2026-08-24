"""Admin module initialization."""
from .audit_logger import AuditEvent, AuditLogger, EventType
from .dashboard_api import admin_router, create_admin_app, install_admin_api
from .dashboard_enterprise import enterprise_router
from .deps import AdminDependencies, get_admin_deps, get_current_admin_user
from .rbac_api import rbac_router
from .rbac_manager import PermissionScope, RBACManager

__all__ = [
    "AuditLogger",
    "AuditEvent",
    "EventType",
    "AdminDependencies",
    "admin_router",
    "enterprise_router",
    "rbac_router",
    "create_admin_app",
    "install_admin_api",
    "get_admin_deps",
    "get_current_admin_user",
    "RBACManager",
    "PermissionScope",
]
