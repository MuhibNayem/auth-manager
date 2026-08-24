"""Audit logging (CONTRACTS.md §4 audit-log contract).

Durable, append-only audit trail persisted through the unified database
contract (``db.save_audit_event`` / ``save_audit_events`` /
``search_audit_events`` / ``get_audit_statistics`` /
``get_audit_time_series``). The db adapter is responsible for the checksum
hash-chain; this module produces well-formed event documents.

Design:

- 34-member :class:`EventType` enum (stable string values).
- :meth:`AuditLogger.log` enqueues events into an in-memory queue; a
  periodic flush task (started via :meth:`AuditLogger.start`) drains it
  every ``flush_interval_seconds`` and :meth:`AuditLogger.close` performs a
  final flush. ``sync=True`` writes immediately for security-critical events.
- Event documents carry BOTH ``actor``/``target`` (the keys the db search
  contract filters on) and the legacy ``actor_id``/``target_id`` aliases.
- Timestamps are stored as timezone-aware datetimes so db adapters can
  compare them directly.
- CSV export uses the ``csv`` module with ``QUOTE_ALL`` so hostile strings
  (embedded quotes, commas, newlines, formula characters) are always quoted.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from authy_package.db.abstract_db import AbstractDatabase

logger = logging.getLogger("authy.admin.audit")

__all__ = ["EventType", "AuditEvent", "AuditLogger"]


class EventType(Enum):
    """The 34 canonical audit event types."""

    # Authentication
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILED = "auth.login.failed"
    LOGOUT = "auth.logout"
    PASSWORD_CHANGED = "auth.password.changed"
    PASSWORD_RESET_REQUESTED = "auth.password.reset_requested"
    PASSWORD_RESET_COMPLETED = "auth.password.reset_completed"

    # User management
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_VERIFIED = "user.verified"

    # Session management
    SESSION_CREATED = "session.created"
    SESSION_REVOKED = "session.revoked"
    SESSION_EXPIRED = "session.expired"

    # MFA
    MFA_ENABLED = "mfa.enabled"
    MFA_DISABLED = "mfa.disabled"
    MFA_CODE_VERIFIED = "mfa.code.verified"
    MFA_CODE_FAILED = "mfa.code.failed"

    # Social auth
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


#: Event types treated as security-relevant by :meth:`AuditLogger.security_events`.
SECURITY_EVENT_TYPES: Tuple[EventType, ...] = (
    EventType.SUSPICIOUS_ACTIVITY,
    EventType.RATE_LIMIT_EXCEEDED,
    EventType.ACCOUNT_LOCKED,
    EventType.ACCOUNT_UNLOCKED,
    EventType.LOGIN_FAILED,
    EventType.MFA_CODE_FAILED,
)

#: Column order for CSV export.
_CSV_COLUMNS = (
    "id",
    "timestamp",
    "event_type",
    "actor",
    "actor_email",
    "target",
    "target_type",
    "action",
    "ip_address",
    "user_agent",
    "organization_id",
    "severity",
    "status",
    "metadata",
)


def _utcnow() -> datetime:
    """Timezone-aware UTC now (CONTRACTS §0.5)."""
    return datetime.now(timezone.utc)


def _coerce_event_type(event_type: "EventType | str") -> EventType:
    """Accept either an enum member or its string value."""
    if isinstance(event_type, EventType):
        return event_type
    return EventType(event_type)


def _serialize_timestamp(value: Any) -> Any:
    """Render datetimes as ISO-8601 strings for export payloads."""
    if isinstance(value, datetime):
        return value.isoformat()
    return value


@dataclass
class AuditEvent:
    """One audit event as an in-memory record."""

    id: str
    event_type: str
    action: str
    timestamp: datetime
    actor: Optional[str] = None
    actor_email: Optional[str] = None
    target: Optional[str] = None
    target_type: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    organization_id: Optional[str] = None
    severity: str = "info"  # info | warning | error | critical
    status: str = "success"  # success | failure

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to the db-contract event document shape."""
        return {
            "id": self.id,
            "event_type": self.event_type,
            "actor": self.actor,
            "actor_id": self.actor,  # legacy alias kept for compatibility
            "actor_email": self.actor_email,
            "target": self.target,
            "target_id": self.target,  # legacy alias
            "target_type": self.target_type,
            "action": self.action,
            "timestamp": self.timestamp,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "metadata": dict(self.metadata or {}),
            "organization_id": self.organization_id,
            "severity": self.severity,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        """Build an :class:`AuditEvent` from a stored document."""
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        elif timestamp is None:
            timestamp = _utcnow()
        return cls(
            id=str(data.get("id", "")),
            event_type=str(data.get("event_type", "")),
            action=str(data.get("action", "")),
            timestamp=timestamp,
            actor=data.get("actor", data.get("actor_id")),
            actor_email=data.get("actor_email"),
            target=data.get("target", data.get("target_id")),
            target_type=data.get("target_type"),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            metadata=dict(data.get("metadata") or {}),
            organization_id=data.get("organization_id"),
            severity=str(data.get("severity", "info")),
            status=str(data.get("status", "success")),
        )


class AuditLogger:
    """Batched audit logger persisted via the §4 database contract.

    Usage::

        audit = AuditLogger(db)
        audit.start()  # optional periodic flush task
        await audit.log(EventType.LOGIN_SUCCESS, "User logged in",
                        actor_id=user_id, sync=True)
        events, total = await audit.search(actor=user_id)
        await audit.close()  # final flush
    """

    def __init__(
        self,
        db: AbstractDatabase,
        *,
        flush_interval_seconds: float = 5.0,
        queue_limit: int = 100,
        retention_days: int = 365,
    ) -> None:
        if queue_limit <= 0:
            raise ValueError("queue_limit must be positive")
        if flush_interval_seconds <= 0:
            raise ValueError("flush_interval_seconds must be positive")
        self._db = db
        self._flush_interval = flush_interval_seconds
        self._queue_limit = queue_limit
        self._retention_days = retention_days
        self._queue: List[Dict[str, Any]] = []
        self._flush_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        """Start the periodic flush task on the current event loop."""
        if self._flush_task is not None and not self._flush_task.done():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.debug("AuditLogger.start() called without a running loop")
            return
        self._flush_task = loop.create_task(self._flush_loop())

    async def close(self) -> None:
        """Cancel the flush task and flush any queued events."""
        if self._flush_task is not None:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._flush_task = None
        await self.flush()

    async def _flush_loop(self) -> None:
        """Periodically drain the queue until cancelled."""
        try:
            while True:
                await asyncio.sleep(self._flush_interval)
                await self.flush()
        except asyncio.CancelledError:
            raise

    # -- writing --------------------------------------------------------------

    async def log(
        self,
        event_type: "EventType | str",
        action: str,
        *,
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
        sync: bool = False,
    ) -> AuditEvent:
        """Record an audit event.

        With ``sync=True`` the event is written immediately (used for
        security-critical events); otherwise it is queued and flushed by the
        periodic task or when the queue reaches ``queue_limit``.
        """
        event = AuditEvent(
            id=secrets.token_hex(16),
            event_type=_coerce_event_type(event_type).value,
            action=str(action),
            timestamp=_utcnow(),
            actor=actor_id,
            actor_email=actor_email,
            target=target_id,
            target_type=target_type,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=dict(metadata or {}),
            organization_id=organization_id,
            severity=severity,
            status=status,
        )
        document = event.to_dict()
        if sync:
            await self._db.save_audit_event(document)
            return event
        async with self._lock:
            self._queue.append(document)
            overflow = len(self._queue) >= self._queue_limit
        if overflow:
            await self.flush()
        return event

    async def flush(self) -> int:
        """Persist all queued events; returns the number written."""
        async with self._lock:
            if not self._queue:
                return 0
            pending, self._queue = self._queue, []
        try:
            await self._db.save_audit_events(pending)
        except Exception:
            # Re-queue on failure so events are not lost, then surface it.
            async with self._lock:
                self._queue = pending + self._queue
            logger.exception("Audit flush failed; events re-queued")
            raise
        return len(pending)

    # -- querying -------------------------------------------------------------

    async def search(
        self,
        *,
        event_types: Optional[List[str]] = None,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Search the audit trail via the db contract; returns (rows, total)."""
        return await self._db.search_audit_events(
            event_types=list(event_types) if event_types else None,
            actor=actor,
            target=target,
            start=start,
            end=end,
            limit=limit,
            offset=offset,
        )

    async def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Fetch one audit event by id."""
        return await self._db.get_audit_event(event_id)

    async def user_timeline(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Recent events where the user is the actor."""
        rows, _ = await self.search(actor=user_id, limit=limit)
        return rows

    async def security_events(
        self,
        *,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Recent security-relevant events (failed logins, lockouts, ...)."""
        rows, _ = await self.search(
            event_types=[event.value for event in SECURITY_EVENT_TYPES],
            start=since,
            limit=limit,
        )
        return rows

    async def get_statistics(self, *, since: Optional[datetime] = None) -> Dict[str, Any]:
        """Aggregate statistics from the db contract."""
        return await self._db.get_audit_statistics(since=since)

    async def get_time_series(
        self, *, since: datetime, bucket_seconds: int
    ) -> List[Dict[str, Any]]:
        """Bucketed event counts from the db contract."""
        return await self._db.get_audit_time_series(
            since=since, bucket_seconds=bucket_seconds
        )

    async def cleanup_old_events(self) -> int:
        """Prune events older than the retention window."""
        cutoff = _utcnow() - timedelta(days=self._retention_days)
        return await self._db.delete_audit_events_before(cutoff)

    # -- export -----------------------------------------------------------------

    async def export_events(
        self,
        *,
        event_types: Optional[List[str]] = None,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 10000,
        format: str = "json",
    ) -> str:
        """Export matching events as JSON or CSV (CSV uses QUOTE_ALL)."""
        rows, _total = await self.search(
            event_types=event_types,
            actor=actor,
            target=target,
            start=start,
            end=end,
            limit=limit,
        )
        if format == "json":
            return json.dumps(
                [self._export_dict(row) for row in rows], indent=2, default=str
            )
        if format == "csv":
            return self._export_csv(rows)
        raise ValueError(f"Unsupported export format: {format!r}")

    @staticmethod
    def _export_dict(row: Dict[str, Any]) -> Dict[str, Any]:
        return {key: _serialize_timestamp(row.get(key)) for key in _CSV_COLUMNS}

    @staticmethod
    def _export_csv(rows: List[Dict[str, Any]]) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\n")
        writer.writerow(_CSV_COLUMNS)
        for row in rows:
            writer.writerow(
                [
                    json.dumps(row.get("metadata") or {}, default=str)
                    if column == "metadata"
                    else str(_serialize_timestamp(row.get(column)) if row.get(column) is not None else "")
                    for column in _CSV_COLUMNS
                ]
            )
        return buffer.getvalue()
