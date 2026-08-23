"""Admin API dependency injection + authentication (CONTRACTS.md §5).

Canonical FastAPI wiring for the admin surface:

- :class:`AdminDependencies` bundles every service the admin routes need
  and is registered on ``app.state.admin_deps``.
- :func:`get_admin_deps` resolves it (503 when not configured).
- :func:`get_current_admin_user` authenticates via
  ``Depends(HTTPBearer(auto_error=False))`` — bearer token in the
  ``Authorization`` header ONLY, never a query parameter — validates the
  access token with :class:`JWTTokenManager` and requires an admin-grade
  role (``admin``/``owner``/``superadmin``) or an RBAC ``admin:*`` grant.
- :func:`require_org_admin` guards org-scoped routes (org owner/admin or
  platform admin).
- :func:`get_v2_principal` guards every ``/admin/v2`` route and accepts
  either an admin JWT or a hashed ``authy_ak_...`` API key validated
  against the db (§8).
- AuthyError → HTTP status mapping (§1) installed by
  :func:`register_error_handlers`.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from authy_package.config import AuthConfig
from authy_package.db.abstract_db import AbstractDatabase
from authy_package.cache.abstract_cache import AbstractCache
from authy_package.errors import (
    AuthenticationError,
    AuthorizationError,
    AuthyError,
    ConfigError,
    DatabaseError,
    IntegrityError,
    NotFoundError,
    ProviderError,
    RateLimitError,
    TokenError,
)
from authy_package.utils.security import JWTTokenManager

logger = logging.getLogger("authy.admin.deps")

__all__ = [
    "AdminDependencies",
    "API_KEY_PREFIX",
    "ADMIN_ROLES",
    "get_admin_deps",
    "get_current_admin_user",
    "require_org_admin",
    "get_v2_principal",
    "require_v2_scope",
    "register_error_handlers",
    "authy_error_status",
]

#: Prefix of v2 API keys (§8).
API_KEY_PREFIX = "authy_ak_"

#: User roles granting platform-admin access (§5).
ADMIN_ROLES = frozenset({"admin", "owner", "superadmin"})

#: AuthyError -> HTTP status mapping (§1).
_ERROR_STATUS = {
    AuthenticationError: status.HTTP_401_UNAUTHORIZED,
    TokenError: status.HTTP_401_UNAUTHORIZED,
    AuthorizationError: status.HTTP_403_FORBIDDEN,
    NotFoundError: status.HTTP_404_NOT_FOUND,
    IntegrityError: status.HTTP_409_CONFLICT,
    RateLimitError: status.HTTP_429_TOO_MANY_REQUESTS,
    ProviderError: status.HTTP_502_BAD_GATEWAY,
    ConfigError: status.HTTP_500_INTERNAL_SERVER_ERROR,
    DatabaseError: status.HTTP_500_INTERNAL_SERVER_ERROR,
}

#: Bearer extraction — ``auto_error=False`` so missing credentials yield a
#: clean 401 (with WWW-Authenticate) instead of FastAPI's default 403.
_bearer_scheme = HTTPBearer(auto_error=False, description="Admin JWT or API key")


def authy_error_status(error: AuthyError) -> int:
    """Map an AuthyError subclass to its HTTP status code (§1)."""
    for error_class, code in _ERROR_STATUS.items():
        if isinstance(error, error_class):
            return code
    return status.HTTP_500_INTERNAL_SERVER_ERROR


def register_error_handlers(app: Any) -> None:
    """Install AuthyError/ValueError/PermissionError handlers on a FastAPI app."""

    async def _authy_error_handler(request: Request, exc: AuthyError):
        from fastapi.responses import JSONResponse

        status_code = authy_error_status(exc)
        headers = {}
        if isinstance(exc, RateLimitError):
            headers["Retry-After"] = str(exc.retry_after)
        if status_code == status.HTTP_401_UNAUTHORIZED:
            headers["WWW-Authenticate"] = "Bearer"
        return JSONResponse(
            status_code=status_code, content=exc.to_dict(), headers=headers or None
        )

    async def _value_error_handler(request: Request, exc: ValueError):
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "invalid_input", "message": str(exc)},
        )

    async def _permission_error_handler(request: Request, exc: PermissionError):
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "authorization_failed", "message": str(exc)},
        )

    app.add_exception_handler(AuthyError, _authy_error_handler)
    app.add_exception_handler(ValueError, _value_error_handler)
    app.add_exception_handler(PermissionError, _permission_error_handler)


@dataclass
class AdminDependencies:
    """Service bundle for the admin API surface (§5).

    Registered on ``app.state.admin_deps`` by
    :func:`authy_package.admin.dashboard_api.install_admin_api`.
    """

    config: AuthConfig
    db: AbstractDatabase
    cache: AbstractCache
    token_manager: JWTTokenManager
    audit_logger: Any = None
    rbac: Any = None
    orgs: Any = None
    webhooks: Any = None
    sessions: Any = None
    auth_manager: Any = field(default=None)


def get_admin_deps(request: Request) -> AdminDependencies:
    """Resolve :class:`AdminDependencies` from app state (503 if absent)."""
    deps = getattr(request.app.state, "admin_deps", None)
    if deps is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin services not configured",
        )
    return deps


def _public_user_view(user: Dict[str, Any]) -> Dict[str, Any]:
    """User dict without credential material."""
    view = dict(user)
    view.pop("hashed_password", None)
    view.pop("mfa_secret", None)
    return view


async def authenticate_admin_jwt(token: str, deps: AdminDependencies) -> Dict[str, Any]:
    """Validate an admin access token and return the sanitized user.

    Raises:
        AuthenticationError: On any token/user/role failure (uniform 401).
    """
    try:
        payload = deps.token_manager.validate_token(token, expected_type="access")
    except TokenError as exc:
        raise AuthenticationError(exc.message, code=exc.code) from exc

    user = await deps.db.get_user_by_id(payload["sub"])
    if user is None:
        raise AuthenticationError("Invalid credentials", code="token_invalid")
    if not user.get("is_active", True):
        raise AuthenticationError("Account is disabled", code="account_disabled")

    role = str(user.get("role", "user"))
    if role not in ADMIN_ROLES:
        # Fall back to an RBAC admin:* grant when RBAC is configured.
        granted = False
        if deps.rbac is not None:
            granted = await deps.rbac.has_permission(user["id"], "admin:*")
        if not granted:
            raise AuthorizationError("Admin access required")
    return _public_user_view(user)


async def get_current_admin_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Bearer-only admin authentication (§5).

    The token MUST arrive via the ``Authorization: Bearer`` header; query
    parameters are never read.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return await authenticate_admin_jwt(credentials.credentials, deps)
    except AuthyError as exc:
        status_code = authy_error_status(exc)
        raise HTTPException(
            status_code=status_code,
            detail=exc.message,
            headers={"WWW-Authenticate": "Bearer"}
            if status_code == status.HTTP_401_UNAUTHORIZED
            else None,
        ) from exc


async def require_org_admin(
    org_id: str,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Guard for org-scoped routes (§5).

    Passes when the user is a platform admin OR holds the owner/admin role
    in the organization.
    """
    role = str(current_user.get("role", "user"))
    if role in ADMIN_ROLES:
        return current_user
    if deps.orgs is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Organization service not configured",
        )
    org_role = await deps.orgs.get_member_role(org_id, current_user["id"])
    if org_role is None or org_role.value not in ("owner", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization admin access required",
        )
    return current_user


def _hash_api_key(key: str) -> str:
    """sha256 hex digest of an API key (§8: hashed at rest)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


async def get_v2_principal(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    deps: AdminDependencies = Depends(get_admin_deps),
) -> Dict[str, Any]:
    """Authenticate EVERY /admin/v2 request (§8).

    Accepts:
    - ``authy_ak_...`` API keys — sha256-hashed and validated against the
      db (revocation + expiry enforced); or
    - an admin JWT (same rules as :func:`get_current_admin_user`).
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials

    if token.startswith(API_KEY_PREFIX):
        record = await deps.db.get_api_key_by_hash(_hash_api_key(token))
        if record is None or record.get("revoked"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        expires_at = record.get("expires_at")
        if expires_at is not None:
            from datetime import datetime, timezone

            if isinstance(expires_at, str):
                try:
                    expires_at = datetime.fromisoformat(expires_at)
                except ValueError:
                    expires_at = None
            if expires_at is not None:
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                if expires_at <= datetime.now(timezone.utc):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="API key has expired",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
        return {
            "type": "api_key",
            "id": record["id"],
            "name": record.get("name"),
            "scopes": list(record.get("scopes") or []),
        }

    try:
        user = await authenticate_admin_jwt(token, deps)
    except AuthyError as exc:
        raise HTTPException(
            status_code=authy_error_status(exc),
            detail=exc.message,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    user = dict(user)
    user["type"] = "user"
    return user


def require_v2_scope(*required_scopes: str):
    """Dependency factory enforcing API-key scopes on /admin/v2 routes.

    JWT (human admin) principals always pass; API-key principals must hold
    one of ``required_scopes`` or the ``admin:*`` wildcard. Empty scope
    lists on a key mean no access to scope-guarded routes.
    """

    async def checker(
        principal: Dict[str, Any] = Depends(get_v2_principal),
    ) -> Dict[str, Any]:
        if principal.get("type") != "api_key":
            return principal
        scopes = set(principal.get("scopes") or [])
        if "admin:*" in scopes:
            return principal
        if scopes.intersection(required_scopes):
            return principal
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"API key missing required scope (one of {sorted(required_scopes)})",
        )

    return checker


def new_admin_router(**kwargs: Any) -> APIRouter:
    """Small helper kept for parity; routers are defined in their modules."""
    return APIRouter(**kwargs)
