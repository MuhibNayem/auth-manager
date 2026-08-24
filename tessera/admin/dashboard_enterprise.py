"""Admin v2 (enterprise) API — REAL implementations (CONTRACTS.md §8).

Everything here persists through the §4 db contract; nothing is mocked:

- **API keys**: plaintext returned ONCE at creation
  (``tessera_ak_`` + ``secrets.token_hex(32)``); only the sha256 hash is
  stored via ``db.save_api_key``. Every ``/admin/v2`` route authenticates
  the bearer (API key or admin JWT) through
  :func:`~tessera.admin.deps.get_v2_principal`.
- **Branding/localization/settings**: persisted via the db settings kv.
- **Reports**: real CSV/JSON generated from users/audit data; job ids are
  ``secrets.token_hex(8)``; downloads served from the settings kv.
- **Bulk user actions**: real db operations, bounded to 1000 ids, audited
  per action.
- **Security analytics**: RULE-BASED heuristics over audit events (brute
  force, impossible-travel proxy via rapid IP change, MFA failure spikes).
  These are deterministic detectors, NOT AI/ML models.
- **Advanced audit search**: structured filters compiled to
  ``db.search_audit_events`` kwargs.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from tessera.admin.audit_logger import EventType
from tessera.admin.deps import (
    AdminDependencies,
    get_admin_deps,
    get_v2_principal,
    require_v2_scope,
)
from tessera.errors import NotFoundError

logger = logging.getLogger("tessera.admin.enterprise")

__all__ = ["enterprise_router"]

enterprise_router = APIRouter(
    prefix="/admin/v2",
    tags=["Enterprise"],
    dependencies=[Depends(get_v2_principal)],
)

#: Settings kv keys (db settings contract).
BRANDING_SETTING_KEY = "admin:branding"
LOCALIZATION_SETTING_KEY = "admin:localization"
REPORT_INDEX_KEY = "admin:report:index"
REPORT_KEY_TEMPLATE = "admin:report:{job_id}"

#: Default branding/localization documents.
DEFAULT_BRANDING: Dict[str, Any] = {
    "app_name": "Tessera Admin",
    "primary_color": "#3B82F6",
    "logo_url": None,
    "favicon_url": None,
    "support_email": None,
    "custom_css": None,
}
DEFAULT_LOCALIZATION: Dict[str, Any] = {
    "default_locale": "en-US",
    "supported_locales": ["en-US"],
    "timezone": "UTC",
}

#: User report CSV columns.
_USER_REPORT_COLUMNS = (
    "id",
    "username",
    "email",
    "phone",
    "role",
    "is_active",
    "mfa_enabled",
    "created_at",
)


def _utcnow() -> datetime:
    """Timezone-aware UTC now (§0.5)."""
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# schemas
# ---------------------------------------------------------------------------

class CreateApiKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    scopes: List[str] = Field(
        ...,
        min_length=1,
        description="e.g. read:only, audit:logs, user:manage, admin:*",
    )
    expires_in_days: Optional[int] = Field(default=30, ge=1, le=3650)


class BrandingConfig(BaseModel):
    app_name: str = "Tessera Admin"
    primary_color: str = "#3B82F6"
    logo_url: Optional[str] = None
    favicon_url: Optional[str] = None
    support_email: Optional[str] = None
    custom_css: Optional[str] = None


class LocalizationConfig(BaseModel):
    default_locale: str = "en-US"
    supported_locales: List[str] = Field(default_factory=lambda: ["en-US"])
    timezone: str = "UTC"


class SettingValue(BaseModel):
    value: Any


class GenerateReportRequest(BaseModel):
    report_type: Literal["users", "audit"]
    format: Literal["csv", "json"] = "csv"
    start: Optional[datetime] = None  # audit reports only
    end: Optional[datetime] = None  # audit reports only
    limit: int = Field(default=10000, ge=1, le=50000)


class BulkActionRequest(BaseModel):
    user_ids: List[str] = Field(..., min_length=1)
    action: Literal["enable", "disable", "delete", "force_password_reset"]
    reason: Optional[str] = None


class AuditSearchFilter(BaseModel):
    event_types: Optional[List[str]] = None
    actor: Optional[str] = None
    target: Optional[str] = None
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------

@enterprise_router.post(
    "/api-keys",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_v2_scope("admin:*"))],
)
async def create_api_key(
    body: CreateApiKeyRequest,
    principal: Dict[str, Any] = Depends(get_v2_principal),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Create an API key. The plaintext key is returned ONCE here only."""
    plaintext = "tessera_ak_" + secrets.token_hex(32)
    key_hash = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    expires_at = (
        _utcnow() + timedelta(days=body.expires_in_days)
        if body.expires_in_days
        else None
    )
    record = await deps.db.save_api_key(
        {
            "name": body.name,
            "key_hash": key_hash,
            "prefix": plaintext[:16],
            "scopes": list(body.scopes),
            "expires_at": expires_at,
            "created_by": principal.get("id"),
            "created_at": _utcnow(),
            "last_used_at": None,
        }
    )
    view = dict(record)
    view.pop("key_hash", None)
    view["api_key"] = plaintext  # shown exactly once
    return view


@enterprise_router.get(
    "/api-keys",
    dependencies=[Depends(require_v2_scope("read:only", "api_keys:read"))],
)
async def list_api_keys(
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """List API key records (hashes never exposed)."""
    records = await deps.db.list_api_keys()
    views = []
    for record in records:
        view = dict(record)
        view.pop("key_hash", None)
        views.append(view)
    return {"api_keys": views, "total": len(views)}


@enterprise_router.delete(
    "/api-keys/{key_id}",
    dependencies=[Depends(require_v2_scope("admin:*"))],
)
async def revoke_api_key(
    key_id: str,
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Revoke an API key."""
    if not await deps.db.revoke_api_key(key_id):
        raise NotFoundError(f"API key {key_id!r} does not exist")
    return {"status": "revoked", "id": key_id}


# ---------------------------------------------------------------------------
# branding / localization / settings (db settings kv)
# ---------------------------------------------------------------------------

@enterprise_router.get(
    "/config/branding",
    dependencies=[Depends(require_v2_scope("read:only", "config:read"))],
)
async def get_branding(
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Current branding settings (defaults when unset)."""
    stored = await deps.db.get_setting(BRANDING_SETTING_KEY)
    merged = dict(DEFAULT_BRANDING)
    if isinstance(stored, dict):
        merged.update(stored)
    return merged


@enterprise_router.put(
    "/config/branding",
    dependencies=[Depends(require_v2_scope("admin:*"))],
)
async def update_branding(
    body: BrandingConfig,
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Persist branding settings via the db settings kv."""
    value = body.model_dump()
    await deps.db.set_setting(BRANDING_SETTING_KEY, value)
    return value


@enterprise_router.get(
    "/config/localization",
    dependencies=[Depends(require_v2_scope("read:only", "config:read"))],
)
async def get_localization(
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Current localization settings (defaults when unset)."""
    stored = await deps.db.get_setting(LOCALIZATION_SETTING_KEY)
    merged = dict(DEFAULT_LOCALIZATION)
    if isinstance(stored, dict):
        merged.update(stored)
    return merged


@enterprise_router.put(
    "/config/localization",
    dependencies=[Depends(require_v2_scope("admin:*"))],
)
async def update_localization(
    body: LocalizationConfig,
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Persist localization settings via the db settings kv."""
    value = body.model_dump()
    await deps.db.set_setting(LOCALIZATION_SETTING_KEY, value)
    return value


@enterprise_router.get(
    "/settings/{key}",
    dependencies=[Depends(require_v2_scope("read:only", "settings:read"))],
)
async def get_setting(
    key: str,
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Fetch one arbitrary setting from the kv store."""
    value = await deps.db.get_setting(f"admin:settings:{key}")
    return {"key": key, "value": value}


@enterprise_router.put(
    "/settings/{key}",
    dependencies=[Depends(require_v2_scope("admin:*"))],
)
async def set_setting(
    key: str,
    body: SettingValue,
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Persist one arbitrary JSON-serializable setting."""
    await deps.db.set_setting(f"admin:settings:{key}", body.value)
    return {"key": key, "value": body.value}


# ---------------------------------------------------------------------------
# reports (real generation from db data)
# ---------------------------------------------------------------------------

def _render_user_report(rows: List[Dict[str, Any]], format: str) -> str:
    """Render users as CSV (QUOTE_ALL) or JSON."""
    if format == "json":
        return json.dumps(rows, indent=2, default=str)
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow(_USER_REPORT_COLUMNS)
    for row in rows:
        writer.writerow([str(row.get(column) if row.get(column) is not None else "")
                         for column in _USER_REPORT_COLUMNS])
    return buffer.getvalue()


@enterprise_router.post(
    "/reports/generate",
    dependencies=[Depends(require_v2_scope("read:only", "audit:logs", "user:manage"))],
)
async def generate_report(
    body: GenerateReportRequest,
    principal: Dict[str, Any] = Depends(get_v2_principal),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Generate a REAL report from users/audit data.

    The artifact is stored under ``admin:report:{job_id}`` in the settings
    kv; job ids are ``secrets.token_hex(8)``.
    """
    if body.report_type == "users":
        rows, _total = await deps.db.list_users(limit=body.limit, offset=0)
        rows = [
            {column: row.get(column) for column in _USER_REPORT_COLUMNS}
            for row in rows
        ]
        content = _render_user_report(rows, body.format)
    else:  # audit
        if deps.audit_logger is not None:
            content = await deps.audit_logger.export_events(
                start=body.start, end=body.end, limit=body.limit, format=body.format
            )
        else:
            audit_rows, _total = await deps.db.search_audit_events(
                start=body.start, end=body.end, limit=body.limit
            )
            if body.format == "json":
                content = json.dumps(audit_rows, indent=2, default=str)
            else:
                from tessera.admin.audit_logger import AuditLogger

                content = AuditLogger._export_csv(audit_rows)
        rows = []

    job_id = secrets.token_hex(8)
    generated_at = _utcnow()
    await deps.db.set_setting(
        REPORT_KEY_TEMPLATE.format(job_id=job_id),
        {
            "job_id": job_id,
            "report_type": body.report_type,
            "format": body.format,
            "content": content,
            "rows": len(rows) if body.report_type == "users" else None,
            "generated_at": generated_at.isoformat(),
            "created_by": principal.get("id"),
        },
    )
    index = await deps.db.get_setting(REPORT_INDEX_KEY) or []
    index.append(
        {
            "job_id": job_id,
            "report_type": body.report_type,
            "format": body.format,
            "generated_at": generated_at.isoformat(),
        }
    )
    await deps.db.set_setting(REPORT_INDEX_KEY, index[-100:])
    logger.info("Generated %s report %s (%s)", body.report_type, job_id, body.format)
    return {
        "job_id": job_id,
        "status": "completed",
        "report_type": body.report_type,
        "format": body.format,
        "generated_at": generated_at.isoformat(),
        "download_url": f"/admin/v2/reports/{job_id}/download",
    }


@enterprise_router.get(
    "/reports",
    dependencies=[Depends(require_v2_scope("read:only", "reports:read"))],
)
async def list_reports(
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """List generated report jobs (metadata only)."""
    index = await deps.db.get_setting(REPORT_INDEX_KEY) or []
    return {"reports": index, "total": len(index)}


@enterprise_router.get(
    "/reports/{job_id}/download",
    dependencies=[Depends(require_v2_scope("read:only", "reports:read"))],
)
async def download_report(
    job_id: str,
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Response:
    """Download a previously generated report."""
    record = await deps.db.get_setting(REPORT_KEY_TEMPLATE.format(job_id=job_id))
    if not isinstance(record, dict) or "content" not in record:
        raise NotFoundError(f"Report {job_id!r} does not exist")
    media_type = (
        "text/csv" if record.get("format") == "csv" else "application/json"
    )
    filename = f"tessera_report_{job_id}.{record.get('format', 'bin')}"
    return Response(
        content=record["content"],
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------------------------------------------------------------------
# bulk user actions (real, bounded, audited)
# ---------------------------------------------------------------------------

@enterprise_router.post(
    "/users/bulk-action",
    dependencies=[Depends(require_v2_scope("user:manage"))],
)
async def perform_bulk_action(
    body: BulkActionRequest,
    principal: Dict[str, Any] = Depends(get_v2_principal),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Apply enable/disable/delete/force_password_reset to up to 1000 users."""
    if len(body.user_ids) > 1000:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Bulk actions are limited to 1000 user_ids",
        )
    succeeded: List[str] = []
    failed: List[Dict[str, Any]] = []
    for user_id in body.user_ids:
        try:
            if body.action == "delete":
                await deps.db.revoke_all_user_sessions(user_id)
                if not await deps.db.delete_user(user_id):
                    failed.append({"user_id": user_id, "reason": "User not found"})
                    continue
            elif body.action in ("enable", "disable"):
                updated = await deps.db.update_user(
                    user_id, {"is_active": body.action == "enable"}
                )
                if updated is None:
                    failed.append({"user_id": user_id, "reason": "User not found"})
                    continue
                if body.action == "disable":
                    await deps.db.revoke_all_user_sessions(user_id)
            else:  # force_password_reset
                updated = await deps.db.update_user(
                    user_id, {"must_reset_password": True}
                )
                if updated is None:
                    failed.append({"user_id": user_id, "reason": "User not found"})
                    continue
            succeeded.append(user_id)
            if deps.audit_logger is not None:
                await deps.audit_logger.log(
                    EventType.ADMIN_ACTION,
                    f"Bulk v2 {body.action} applied to user {user_id}",
                    actor_id=str(principal.get("id")),
                    target_id=user_id,
                    target_type="user",
                    metadata={"action": body.action, "reason": body.reason},
                    severity="warning" if body.action == "delete" else "info",
                    sync=True,
                )
        except Exception as exc:  # noqa: BLE001 - continue batch
            failed.append({"user_id": user_id, "reason": type(exc).__name__})
    return {
        "action": body.action,
        "processed_count": len(succeeded),
        "failed_ids": failed,
        "succeeded": succeeded,
    }


# ---------------------------------------------------------------------------
# security analytics (rule-based heuristics — NOT AI)
# ---------------------------------------------------------------------------

#: Seconds between logins below which an IP change is flagged.
IMPOSSIBLE_TRAVEL_WINDOW_SECONDS = 1800


@enterprise_router.get(
    "/security/analytics",
    dependencies=[Depends(require_v2_scope("read:only", "audit:logs"))],
)
async def security_analytics(
    window_hours: int = Query(default=24, ge=1, le=720),
    brute_force_threshold: int = Query(default=5, ge=2),
    mfa_spike_threshold: int = Query(default=5, ge=2),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Rule-based security detectors over audit events.

    HEURISTICS, not AI/ML:

    - ``brute_force``: >= ``brute_force_threshold`` failed logins per
      (identifier, ip) inside the window.
    - ``impossible_travel_proxy``: successful logins for one actor from
      different IPs less than 30 minutes apart (IP-change velocity; no
      geolocation is used or claimed).
    - ``mfa_failure_spike``: >= ``mfa_spike_threshold`` failed MFA codes
      per actor inside the window.
    """
    now = _utcnow()
    window_start = now - timedelta(hours=window_hours)
    incidents: List[Dict[str, Any]] = []

    # -- brute force -----------------------------------------------------
    failed_rows, _failed_total = await deps.db.search_audit_events(
        event_types=[EventType.LOGIN_FAILED.value],
        start=window_start,
        limit=5000,
    )
    buckets: Dict[tuple, Dict[str, Any]] = {}
    for row in failed_rows:
        identifier = (
            row.get("target")
            or (row.get("metadata") or {}).get("identifier")
            or row.get("actor")
            or "unknown"
        )
        key = (str(identifier), str(row.get("ip_address") or "unknown"))
        bucket = buckets.setdefault(
            key,
            {"count": 0, "first_at": None, "last_at": None},
        )
        bucket["count"] += 1
        ts = row.get("timestamp")
        if ts is not None:
            ts = _ensure_aware(ts)
            if bucket["first_at"] is None or ts < bucket["first_at"]:
                bucket["first_at"] = ts
            if bucket["last_at"] is None or ts > bucket["last_at"]:
                bucket["last_at"] = ts
    for (identifier, ip_address), bucket in buckets.items():
        if bucket["count"] >= brute_force_threshold:
            incidents.append(
                {
                    "type": "brute_force",
                    "severity": "high",
                    "identifier": identifier,
                    "ip_address": ip_address,
                    "count": bucket["count"],
                    "first_at": bucket["first_at"].isoformat()
                    if bucket["first_at"]
                    else None,
                    "last_at": bucket["last_at"].isoformat()
                    if bucket["last_at"]
                    else None,
                }
            )

    # -- impossible-travel proxy (rapid IP change) -------------------------
    success_rows, _success_total = await deps.db.search_audit_events(
        event_types=[EventType.LOGIN_SUCCESS.value],
        start=window_start,
        limit=5000,
    )
    by_actor: Dict[str, List[Dict[str, Any]]] = {}
    for row in success_rows:
        actor = row.get("actor")
        if actor and row.get("ip_address"):
            by_actor.setdefault(str(actor), []).append(row)
    for actor, rows in by_actor.items():
        rows.sort(key=lambda r: _ensure_aware(r.get("timestamp") or now))
        previous: Optional[Dict[str, Any]] = None
        for row in rows:
            if previous is not None and row.get("ip_address") != previous.get(
                "ip_address"
            ):
                delta = (
                    _ensure_aware(row["timestamp"])
                    - _ensure_aware(previous["timestamp"])
                ).total_seconds()
                if 0 <= delta <= IMPOSSIBLE_TRAVEL_WINDOW_SECONDS:
                    incidents.append(
                        {
                            "type": "impossible_travel_proxy",
                            "severity": "medium",
                            "actor": actor,
                            "from_ip": previous.get("ip_address"),
                            "to_ip": row.get("ip_address"),
                            "seconds_between": round(delta, 1),
                        }
                    )
            previous = row

    # -- MFA failure spikes ------------------------------------------------
    mfa_rows, _mfa_total = await deps.db.search_audit_events(
        event_types=[EventType.MFA_CODE_FAILED.value],
        start=window_start,
        limit=5000,
    )
    mfa_counts: Dict[str, int] = {}
    for row in mfa_rows:
        actor = str(row.get("actor") or "unknown")
        mfa_counts[actor] = mfa_counts.get(actor, 0) + 1
    for actor, count in mfa_counts.items():
        if count >= mfa_spike_threshold:
            incidents.append(
                {
                    "type": "mfa_failure_spike",
                    "severity": "medium",
                    "actor": actor,
                    "count": count,
                }
            )

    return {
        "generated_at": now.isoformat(),
        "window_hours": window_hours,
        "heuristic": True,
        "method": "rule-based detectors over audit events (no AI/ML)",
        "detectors": {
            "brute_force": {"threshold": brute_force_threshold},
            "impossible_travel_proxy": {
                "window_seconds": IMPOSSIBLE_TRAVEL_WINDOW_SECONDS,
                "note": "IP-change velocity only; no geolocation",
            },
            "mfa_failure_spike": {"threshold": mfa_spike_threshold},
        },
        "counts": {
            "failed_logins": len(failed_rows),
            "successful_logins": len(success_rows),
            "mfa_failures": len(mfa_rows),
        },
        "incidents": incidents,
        "total_incidents": len(incidents),
    }


# ---------------------------------------------------------------------------
# advanced audit search (compiled to search_audit_events kwargs)
# ---------------------------------------------------------------------------

@enterprise_router.post(
    "/audit-logs/search",
    dependencies=[Depends(require_v2_scope("read:only", "audit:logs"))],
)
async def advanced_audit_search(
    filters: AuditSearchFilter,
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Structured audit search compiled to db.search_audit_events kwargs."""
    kwargs: Dict[str, Any] = {
        "event_types": filters.event_types,
        "actor": filters.actor,
        "target": filters.target,
        "start": filters.start,
        "end": filters.end,
        "limit": filters.limit,
        "offset": filters.offset,
    }
    rows, total = await deps.db.search_audit_events(**kwargs)
    return {
        "events": rows,
        "total": total,
        "applied_filters": filters.model_dump(mode="json"),
    }
