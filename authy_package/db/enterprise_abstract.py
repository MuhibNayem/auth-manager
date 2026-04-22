"""
Enterprise-grade Abstract Database Interface.
Defines the complete contract for all data operations in Authy.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union, Tuple
from datetime import datetime
import uuid

# Type aliases for clarity
UserID = str
OrgID = str
SessionID = str
AuditLogID = str


class DatabaseError(Exception):
    """Base exception for database errors."""
    pass

class ConnectionError(DatabaseError):
    """Raised when connection to the database fails."""
    pass

class IntegrityError(DatabaseError):
    """Raised when database integrity constraints are violated."""
    pass

class NotFoundError(DatabaseError):
    """Raised when a requested resource is not found."""
    pass


class EnterpriseDatabaseAdapter(ABC):
    """
    Abstract base class for all enterprise database adapters.
    Ensures consistent API across SQL, NoSQL, and NewSQL databases.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.pool = None
        self.is_connected = False

    @abstractmethod
    async def connect(self) -> None:
        """Initialize connection pool and verify connectivity."""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Gracefully close all connections."""
        pass

    # ==================== USER MANAGEMENT ====================

    @abstractmethod
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user. Raises IntegrityError if unique constraint violated."""
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: UserID) -> Optional[Dict[str, Any]]:
        """Fetch user by primary ID."""
        pass

    @abstractmethod
    async def get_user_by_identifier(self, identifier: str, identifier_type: str = 'email') -> Optional[Dict[str, Any]]:
        """Fetch user by email, username, or other unique identifier."""
        pass

    @abstractmethod
    async def update_user(self, user_id: UserID, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Partial update of user fields."""
        pass

    @abstractmethod
    async def delete_user(self, user_id: UserID) -> bool:
        """Soft or hard delete user."""
        pass

    @abstractmethod
    async def list_users(self, org_id: Optional[OrgID] = None, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """List users with pagination and optional org filtering."""
        pass

    # ==================== ORGANIZATION & TENANCY ====================

    @abstractmethod
    async def create_organization(self, org_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new organization/tenant."""
        pass

    @abstractmethod
    async def get_organization(self, org_id: OrgID) -> Optional[Dict[str, Any]]:
        """Get organization by ID or slug."""
        pass

    @abstractmethod
    async def update_organization(self, org_id: OrgID, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update organization details."""
        pass

    @abstractmethod
    async def add_org_member(self, org_id: OrgID, user_id: UserID, role: str) -> Dict[str, Any]:
        """Add a user to an organization with a specific role."""
        pass

    @abstractmethod
    async def remove_org_member(self, org_id: OrgID, user_id: UserID) -> bool:
        """Remove a user from an organization."""
        pass

    @abstractmethod
    async def get_org_members(self, org_id: OrgID, role_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all members of an organization."""
        pass

    @abstractmethod
    async def get_user_orgs(self, user_id: UserID) -> List[Dict[str, Any]]:
        """Get all organizations a user belongs to."""
        pass

    # ==================== SESSION MANAGEMENT ====================

    @abstractmethod
    async def create_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user session."""
        pass

    @abstractmethod
    async def get_session(self, session_id: SessionID) -> Optional[Dict[str, Any]]:
        """Retrieve session by ID."""
        pass

    @abstractmethod
    async def update_session(self, session_id: SessionID, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update session (e.g., refresh token, last_active)."""
        pass

    @abstractmethod
    async def revoke_session(self, session_id: SessionID) -> bool:
        """Invalidate a specific session."""
        pass

    @abstractmethod
    async def revoke_all_user_sessions(self, user_id: UserID, exclude_session_id: Optional[SessionID] = None) -> int:
        """Revoke all sessions for a user (optionally excluding current)."""
        pass

    @abstractmethod
    async def get_active_sessions(self, user_id: UserID) -> List[Dict[str, Any]]:
        """Get all active sessions for a user."""
        pass

    # ==================== AUDIT LOGGING ====================

    @abstractmethod
    async def write_audit_log(self, log_entry: Dict[str, Any]) -> AuditLogID:
        """Append an immutable audit log entry."""
        pass

    @abstractmethod
    async def query_audit_logs(
        self, 
        filters: Dict[str, Any], 
        start_date: datetime, 
        end_date: datetime, 
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Search audit logs with complex filters."""
        pass

    @abstractmethod
    async def export_audit_logs(
        self, 
        filters: Dict[str, Any], 
        format: str = 'json'
    ) -> bytes:
        """Export audit logs to JSON or CSV."""
        pass

    # ==================== MFA & SECURITY ====================

    @abstractmethod
    async def save_mfa_secret(self, user_id: UserID, secret_data: Dict[str, Any]) -> None:
        """Store TOTP/WebAuthn secrets."""
        pass

    @abstractmethod
    async def get_mfa_secret(self, user_id: UserID) -> Optional[Dict[str, Any]]:
        """Retrieve MFA secrets for a user."""
        pass

    @abstractmethod
    async def record_login_attempt(self, user_id: UserID, success: bool, ip: str, user_agent: str) -> None:
        """Record login attempt for rate limiting and lockout logic."""
        pass

    @abstractmethod
    async def get_failed_login_count(self, user_id: UserID, window_minutes: int) -> int:
        """Count failed logins within a time window."""
        pass

    # ==================== WEBHOOKS ====================

    @abstractmethod
    async def create_webhook_subscription(self, sub_data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new webhook endpoint."""
        pass

    @abstractmethod
    async def get_webhook_subscriptions(self, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List active webhook subscriptions."""
        pass

    @abstractmethod
    async def record_webhook_delivery(self, subscription_id: str, success: bool, response_code: int, payload: str) -> None:
        """Log webhook delivery attempts."""
        pass

    # ==================== SAML & OIDC (Enterprise) ====================

    @abstractmethod
    async def register_saml_provider(self, provider_data: Dict[str, Any]) -> Dict[str, Any]:
        """Configure a SAML Identity Provider."""
        pass

    @abstractmethod
    async def get_saml_provider(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve SAML provider configuration."""
        pass

    @abstractmethod
    async def create_saml_session(self, session_data: Dict[str, Any]) -> str:
        """Store transient SAML session state (RequestID -> State)."""
        pass

    @abstractmethod
    async def consume_saml_session(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve and delete SAML session state."""
        pass

    @abstractmethod
    async def register_oidc_provider(self, provider_data: Dict[str, Any]) -> Dict[str, Any]:
        """Configure an OIDC Identity Provider."""
        pass

    @abstractmethod
    async def get_oidc_provider(self, issuer: str) -> Optional[Dict[str, Any]]:
        """Retrieve OIDC provider configuration."""
        pass

    @abstractmethod
    async def link_external_identity(self, user_id: UserID, provider_type: str, subject: str) -> None:
        """Link an external SAML/OIDC subject to a local user."""
        pass

    @abstractmethod
    async def get_user_by_external_identity(self, provider_type: str, subject: str) -> Optional[Dict[str, Any]]:
        """Find a local user by external SAML/OIDC subject."""
        pass

    # ==================== UTILITIES ====================

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Return detailed health status (latency, connections, version)."""
        pass

    @abstractmethod
    async def run_migration(self, version: str) -> None:
        """Apply database schema migrations."""
        pass
