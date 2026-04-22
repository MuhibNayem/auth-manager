"""
Audit Logging System

Features:
- Comprehensive event tracking
- Immutable audit trail
- Search and filtering
- Compliance ready (SOC2, GDPR)
- Real-time monitoring
- Export capabilities
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from enum import Enum
import json


class EventType(Enum):
    """Audit event types"""
    # Authentication
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILED = "auth.login.failed"
    LOGOUT = "auth.logout"
    PASSWORD_CHANGED = "auth.password.changed"
    PASSWORD_RESET_REQUESTED = "auth.password.reset_requested"
    PASSWORD_RESET_COMPLETED = "auth.password.reset_completed"
    
    # User Management
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_VERIFIED = "user.verified"
    
    # Session Management
    SESSION_CREATED = "session.created"
    SESSION_REVOKED = "session.revoked"
    SESSION_EXPIRED = "session.expired"
    
    # MFA
    MFA_ENABLED = "mfa.enabled"
    MFA_DISABLED = "mfa.disabled"
    MFA_CODE_VERIFIED = "mfa.code.verified"
    MFA_CODE_FAILED = "mfa.code.failed"
    
    # Social Auth
    SOCIAL_LINKED = "social.linked"
    SOCIAL_UNLINKED = "social.unlinked"
    SOCIAL_LOGIN = "social.login"
    
    # Organization
    ORG_CREATED = "org.created"
    ORG_UPDATED = "org.updated"
    MEMBER_ADDED = "org.member.added"
    MEMBER_REMOVED = "org.member.removed"
    ROLE_CHANGED = "org.role.changed"
    INVITATION_SENT = "org.invitation.sent"
    INVITATION_ACCEPTED = "org.invitation.accepted"
    
    # Security
    SUSPICIOUS_ACTIVITY = "security.suspicious"
    RATE_LIMIT_EXCEEDED = "security.rate_limit"
    ACCOUNT_LOCKED = "security.account_locked"
    ACCOUNT_UNLOCKED = "security.account_unlocked"
    
    # Admin
    ADMIN_ACTION = "admin.action"
    DATA_EXPORT = "admin.data_export"
    USER_IMPERSONATION = "admin.user_impersonation"


@dataclass
class AuditEvent:
    """Represents an audit log entry"""
    id: str
    event_type: EventType
    actor_id: Optional[str]
    actor_email: Optional[str]
    target_id: Optional[str]
    target_type: Optional[str]
    action: str
    timestamp: datetime
    ip_address: Optional[str]
    user_agent: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    organization_id: Optional[str] = None
    severity: str = "info"  # info, warning, error, critical
    status: str = "success"  # success, failure


class AuditLogger:
    """
    Comprehensive audit logging system
    
    Usage:
        audit_logger = AuditLogger(config, db, cache)
        await audit_logger.log(
            event_type=EventType.LOGIN_SUCCESS,
            actor_id=user_id,
            action="User logged in successfully",
            ip_address=request_ip
        )
        events = await audit_logger.search(user_id=user_id, limit=100)
    """
    
    def __init__(self, config, db, cache):
        self.config = config
        self.db = db
        self.cache = cache
        self._retention_days = config.audit_log_retention_days or 365
        self._async_queue = []
        self._queue_size_limit = 100
    
    async def log(
        self,
        event_type: EventType,
        action: str,
        actor_id: Optional[str] = None,
        actor_email: Optional[str] = None,
        target_id: Optional[str] = None,
        target_type: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        organization_id: Optional[str] = None,
        severity: str = "info",
        status: str = "success",
        sync: bool = False
    ):
        """
        Log an audit event
        
        Args:
            event_type: Type of event
            action: Human-readable action description
            actor_id: ID of the user who performed the action
            actor_email: Email of the actor
            target_id: ID of the target resource
            target_type: Type of target resource
            ip_address: IP address of the request
            user_agent: User agent string
            metadata: Additional event data
            organization_id: Organization context
            severity: Event severity level
            status: Event status
            sync: If True, write immediately (default: batched)
        """
        event = AuditEvent(
            id=str(uuid.uuid4()),
            event_type=event_type,
            actor_id=actor_id,
            actor_email=actor_email,
            target_id=target_id,
            target_type=target_type,
            action=action,
            timestamp=datetime.utcnow(),
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {},
            organization_id=organization_id,
            severity=severity,
            status=status
        )
        
        if sync or len(self._async_queue) >= self._queue_size_limit:
            await self._write_event(event)
            await self._flush_queue()
        else:
            self._async_queue.append(event)
    
    async def _flush_queue(self):
        """Flush queued events to database"""
        if not self._async_queue:
            return
        
        # Batch write
        events_data = [self._serialize_event(e) for e in self._async_queue]
        await self.db.save_audit_events(events_data)
        self._async_queue = []
    
    async def _write_event(self, event: AuditEvent):
        """Write a single event to database"""
        await self.db.save_audit_event(self._serialize_event(event))
    
    async def search(
        self,
        actor_id: Optional[str] = None,
        event_type: Optional[EventType] = None,
        organization_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditEvent]:
        """
        Search audit logs with filters
        
        Returns:
            List of matching audit events
        """
        filters = {
            "actor_id": actor_id,
            "event_type": event_type.value if event_type else None,
            "organization_id": organization_id,
            "start_date": start_date.isoformat() if start_date else None,
            "end_date": end_date.isoformat() if end_date else None,
            "severity": severity,
            "status": status,
            "limit": limit,
            "offset": offset
        }
        
        # Remove None filters
        filters = {k: v for k, v in filters.items() if v is not None}
        
        events_data = await self.db.search_audit_events(filters)
        return [self._deserialize_event(e) for e in events_data]
    
    async def get_event(self, event_id: str) -> Optional[AuditEvent]:
        """Get a specific audit event by ID"""
        event_data = await self.db.get_audit_event(event_id)
        if not event_data:
            return None
        return self._deserialize_event(event_data)
    
    async def get_user_timeline(
        self,
        user_id: str,
        limit: int = 50
    ) -> List[AuditEvent]:
        """Get audit timeline for a specific user"""
        return await self.search(actor_id=user_id, limit=limit)
    
    async def get_security_events(
        self,
        organization_id: Optional[str] = None,
        limit: int = 100
    ) -> List[AuditEvent]:
        """Get security-related events"""
        security_types = [
            EventType.SUSPICIOUS_ACTIVITY,
            EventType.RATE_LIMIT_EXCEEDED,
            EventType.ACCOUNT_LOCKED,
            EventType.ACCOUNT_UNLOCKED,
            EventType.LOGIN_FAILED
        ]
        
        events = []
        for event_type in security_types:
            type_events = await self.search(
                event_type=event_type,
                organization_id=organization_id,
                limit=limit // len(security_types)
            )
            events.extend(type_events)
        
        # Sort by timestamp descending
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[:limit]
    
    async def export_events(
        self,
        filters: Dict[str, Any],
        format: str = "json"
    ) -> str:
        """
        Export audit events for compliance
        
        Args:
            filters: Search filters
            format: Output format (json, csv)
        
        Returns:
            Exported data as string
        """
        events = await self.search(**filters, limit=10000)
        
        if format == "json":
            return json.dumps([self._serialize_event(e) for e in events], indent=2)
        elif format == "csv":
            return self._export_csv(events)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _export_csv(self, events: List[AuditEvent]) -> str:
        """Export events as CSV"""
        headers = ["id", "timestamp", "event_type", "actor_email", "action", "ip_address", "status", "severity"]
        lines = [",".join(headers)]
        
        for event in events:
            row = [
                event.id,
                event.timestamp.isoformat(),
                event.event_type.value,
                event.actor_email or "",
                event.action.replace(",", ";"),  # Escape commas
                event.ip_address or "",
                event.status,
                event.severity
            ]
            lines.append(",".join(row))
        
        return "\n".join(lines)
    
    async def cleanup_old_events(self):
        """Remove events older than retention period"""
        cutoff_date = datetime.utcnow() - timedelta(days=self._retention_days)
        deleted_count = await self.db.delete_audit_events_before(cutoff_date)
        return deleted_count
    
    async def get_statistics(
        self,
        start_date: datetime,
        end_date: datetime,
        group_by: str = "event_type"
    ) -> Dict[str, Any]:
        """Get audit log statistics"""
        stats = await self.db.get_audit_statistics(start_date, end_date, group_by)
        return stats
    
    def _serialize_event(self, event: AuditEvent) -> Dict:
        """Serialize event for storage"""
        return {
            "id": event.id,
            "event_type": event.event_type.value,
            "actor_id": event.actor_id,
            "actor_email": event.actor_email,
            "target_id": event.target_id,
            "target_type": event.target_type,
            "action": event.action,
            "timestamp": event.timestamp.isoformat(),
            "ip_address": event.ip_address,
            "user_agent": event.user_agent,
            "metadata": event.metadata,
            "organization_id": event.organization_id,
            "severity": event.severity,
            "status": event.status
        }
    
    def _deserialize_event(self, data: Dict) -> AuditEvent:
        """Deserialize event from storage"""
        return AuditEvent(
            id=data["id"],
            event_type=EventType(data["event_type"]),
            actor_id=data.get("actor_id"),
            actor_email=data.get("actor_email"),
            target_id=data.get("target_id"),
            target_type=data.get("target_type"),
            action=data["action"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            metadata=data.get("metadata", {}),
            organization_id=data.get("organization_id"),
            severity=data.get("severity", "info"),
            status=data.get("status", "success")
        )
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - flush remaining events"""
        await self._flush_queue()
