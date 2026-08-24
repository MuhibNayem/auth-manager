"""Compliance module — GDPR tooling and security reporting.

Rebuilt on the §4 database contract:

- Audit checksum semantics live in the db adapter (hash chain); this
  module exposes :func:`verify_audit_chain` as a thin delegation.
- GDPR export/delete operate through ``get_user_by_id``,
  ``get_active_sessions``, ``search_audit_events``, ``update_user`` and
  ``delete_user``.
- Anonymization redacts every field whose name matches ``*token*``,
  ``*secret*`` or ``*password*`` (case-insensitive substring).
- The old crashing aiohttp dashboard server is replaced by a pure async
  report function :func:`build_security_report` returning a dict.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("tessera.compliance")

__all__ = [
    "GDPRComplianceEngine",
    "SOC2AuditLogger",
    "verify_audit_chain",
    "build_security_report",
    "redact_sensitive",
]

#: Field-name patterns considered sensitive (case-insensitive substring).
_SENSITIVE_FIELD_PATTERN = re.compile(r"(token|secret|password)", re.IGNORECASE)

_REDACTED = "[REDACTED]"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def redact_sensitive(data: Any) -> Any:
    """Recursively redact values whose field names match the sensitive
    patterns (``*token*`` / ``*secret*`` / ``*password*``)."""
    if isinstance(data, dict):
        result: Dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(key, str) and _SENSITIVE_FIELD_PATTERN.search(key):
                result[key] = _REDACTED
            else:
                result[key] = redact_sensitive(value)
        return result
    if isinstance(data, list):
        return [redact_sensitive(item) for item in data]
    return data


class GDPRComplianceEngine:
    """GDPR right-to-access and right-to-be-forgotten on the db contract."""

    def __init__(self, db: Any, config: Optional[Dict[str, Any]] = None):
        if db is None:
            raise ValueError("GDPRComplianceEngine requires a database adapter")
        self.db = db
        self.config = config or {}
        self.data_retention_days = self.config.get("data_retention_days", 90)

    async def export_user_data(self, user_id: str) -> Dict[str, Any]:
        """Export all data for a user (GDPR Article 15).

        Sensitive fields are redacted in the export payload.
        """
        user = await self.db.get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        sessions = await self.db.get_active_sessions(user_id)

        # Search audit events by every identifier the user is known by.
        identifiers = {user_id}
        for field in ("email", "username", "phone"):
            if user.get(field):
                identifiers.add(str(user[field]))
        audit_rows: List[Dict[str, Any]] = []
        for identifier in identifiers:
            for actor_field in ({"actor": identifier}, {"target": identifier}):
                rows, _total = await self.db.search_audit_events(
                    limit=500, **actor_field
                )
                audit_rows.extend(rows)
        # De-duplicate by event id, keep newest-first ordering stable.
        seen = set()
        unique_rows: List[Dict[str, Any]] = []
        for row in audit_rows:
            row_id = row.get("id")
            if row_id in seen:
                continue
            seen.add(row_id)
            unique_rows.append(row)

        return {
            "export_date": _utcnow().isoformat(),
            "user": redact_sensitive(user),
            "sessions": redact_sensitive(sessions),
            "audit_logs": redact_sensitive(unique_rows),
            "data_categories": {
                "identity": ["email", "username", "phone", "created_at"],
                "authentication": ["mfa_enabled", "auth_method", "provider"],
                "sessions": ["active_sessions", "device_info"],
            },
        }

    async def delete_user_data(
        self, user_id: str, hard_delete: bool = False
    ) -> Dict[str, Any]:
        """GDPR Article 17: erase or anonymize a user's data."""
        user = await self.db.get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        revoked_sessions = await self.db.revoke_all_user_sessions(user_id)

        if hard_delete:
            deleted = await self.db.delete_user(user_id)
            return {
                "deleted": bool(deleted),
                "revoked_sessions": revoked_sessions,
                "note": "Audit log entries are retained (security trail).",
            }

        anonymized = {
            "email": f"deleted_{user_id}@anonymized.invalid",
            "username": f"deleted_{user_id}",
            "phone": None,
            "hashed_password": None,
            "mfa_secret": None,
            "mfa_backup_codes": [],
            "mfa_enabled": False,
            "is_active": False,
            "is_deleted": True,
            "deleted_at": _utcnow().isoformat(),
        }
        await self.db.update_user(user_id, anonymized)
        return {"anonymized": True, "revoked_sessions": revoked_sessions}


class SOC2AuditLogger:
    """Audit logging delegating checksum semantics to the db adapter."""

    def __init__(self, db: Any, config: Optional[Dict[str, Any]] = None):
        if db is None:
            raise ValueError("SOC2AuditLogger requires a database adapter")
        self.db = db
        self.config = config or {}
        self.enabled = self.config.get("audit_logging", True)

    async def log_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Append one audit event; the db computes checksum + chain link."""
        if not self.enabled:
            return None
        record = dict(event)
        record.setdefault("timestamp", _utcnow().isoformat())
        record.setdefault("status", "success")
        return await self.db.save_audit_event(record)

    async def verify_log_integrity(self) -> bool:
        """Verify the whole audit hash chain (db-owned semantics)."""
        return await verify_audit_chain(self.db)

    async def export_audit_logs(
        self, start_date: datetime, end_date: datetime, limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Export audit events within a window (newest first)."""
        rows, _total = await self.db.search_audit_events(
            start=start_date, end=end_date, limit=limit
        )
        return rows


async def verify_audit_chain(db: Any) -> bool:
    """Re-verify the audit hash chain via the db contract."""
    verifier = getattr(db, "verify_audit_chain", None)
    if verifier is None:
        logger.warning("Database adapter does not expose verify_audit_chain")
        return False
    return bool(await verifier())


def _threat_level(failed_logins: int, suspicious: int) -> str:
    if failed_logins > 1000 or suspicious > 100:
        return "critical"
    if failed_logins > 500 or suspicious > 50:
        return "high"
    if failed_logins > 100 or suspicious > 10:
        return "medium"
    return "low"


async def build_security_report(db: Any) -> Dict[str, Any]:
    """Pure async security report (dict). No server, no external imports.

    Replaces the former aiohttp dashboard: all data comes from the db
    contract (user counts, audit statistics/search, chain verification).
    """
    if db is None:
        raise ValueError("build_security_report requires a database adapter")

    now = _utcnow()
    since_24h = now - timedelta(hours=24)
    since_7d = now - timedelta(days=7)

    total_users = await db.count_users()
    active_users = await db.count_users(active_only=True)
    mfa_users = await db.count_users(mfa_enabled=True)

    stats = await db.get_audit_statistics(since=since_7d)

    failed_login_rows, failed_login_total = await db.search_audit_events(
        event_types=["login_failed", "login.failure"],
        start=since_24h,
        limit=1,
    )
    suspicious_rows, suspicious_total = await db.search_audit_events(
        event_types=["suspicious_activity", "security.alert"],
        start=since_24h,
        limit=1,
    )

    chain_ok = await verify_audit_chain(db)

    return {
        "generated_at": now.isoformat(),
        "period": "last_24_hours",
        "users": {
            "total": total_users,
            "active": active_users,
            "mfa_enabled": mfa_users,
        },
        "audit": {
            "chain_intact": chain_ok,
            "events_last_7_days": stats.get("total_events", 0),
            "events_by_type": stats.get("events_by_type", {}),
        },
        "threats": {
            "failed_login_attempts": failed_login_total,
            "suspicious_activities": suspicious_total,
            "threat_level": _threat_level(failed_login_total, suspicious_total),
        },
    }
