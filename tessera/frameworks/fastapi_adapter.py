"""FastAPI integration adapter (CONTRACTS.md §10).

- ``require_auth`` is a proper dependency built on
  ``Depends(HTTPBearer(auto_error=False))`` — bearer only, 401 with
  ``WWW-Authenticate`` when missing/invalid.
- ``require_role``, ``require_org_membership``, ``optional_auth`` and
  ``rate_limit`` (cache counters, §3.1 key schema) are provided.
- TesseraError subclasses map uniformly to HTTP status codes (§1).

Components (db/cache/token_manager/organizations) may be passed explicitly
or resolved from an ``auth_manager`` object exposing those attributes.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from tessera.errors import (
    AuthenticationError,
    AuthorizationError,
    TesseraError,
    NotFoundError,
    ProviderError,
    RateLimitError,
    TokenError,
)

logger = logging.getLogger("tessera.frameworks.fastapi")

__all__ = ["FastAPIAuth", "tessera_error_to_http_exception", "install_error_handlers"]

#: Rate-limit cache key (§3.1 schema: tessera:ratelimit:{scope}:{id}).
_RATE_LIMIT_KEY_TEMPLATE = "tessera:ratelimit:http:{identifier}"


def tessera_error_to_http_exception(error: TesseraError) -> HTTPException:
    """Map an TesseraError to the HTTPException required by §1."""
    if isinstance(error, (AuthenticationError, TokenError)):
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error.message,
            headers={"WWW-Authenticate": "Bearer"},
        )
    if isinstance(error, AuthorizationError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=error.message)
    if isinstance(error, NotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=error.message)
    if isinstance(error, RateLimitError):
        return HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=error.message,
            headers={"Retry-After": str(error.retry_after)},
        )
    if isinstance(error, ProviderError):
        return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error.message)
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=error.message
    )


def install_error_handlers(app: Any) -> None:
    """Register TesseraError/ValueError handlers on a FastAPI app."""
    from fastapi.responses import JSONResponse

    async def _tessera_handler(request: Request, exc: TesseraError):
        http_exc = tessera_error_to_http_exception(exc)
        return JSONResponse(
            status_code=http_exc.status_code,
            content={"error": exc.code, "message": exc.message},
            headers=http_exc.headers,
        )

    async def _value_error_handler(request: Request, exc: ValueError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "invalid_input", "message": str(exc)},
        )

    app.add_exception_handler(TesseraError, _tessera_handler)
    app.add_exception_handler(ValueError, _value_error_handler)


class FastAPIAuth:
    """FastAPI authentication adapter.

    Usage::

        fastapi_auth = FastAPIAuth(db=db, cache=cache, token_manager=jm)

        @app.get("/protected")
        async def protected(user=Depends(fastapi_auth.require_auth)):
            return {"user": user}

        @app.get("/admin")
        async def admin_only(user=Depends(fastapi_auth.require_role("admin"))):
            return {"ok": True}
    """

    def __init__(
        self,
        auth_manager: Optional[Any] = None,
        *,
        db: Optional[Any] = None,
        cache: Optional[Any] = None,
        token_manager: Optional[Any] = None,
        organizations: Optional[Any] = None,
    ) -> None:
        self.auth_manager = auth_manager
        self.db = db if db is not None else getattr(auth_manager, "db", None)
        self.cache = cache if cache is not None else getattr(auth_manager, "cache", None)
        self.token_manager = (
            token_manager
            if token_manager is not None
            else (
                getattr(auth_manager, "token_manager", None)
                or getattr(auth_manager, "jwt_manager", None)
            )
        )
        self.organizations = (
            organizations
            if organizations is not None
            else getattr(auth_manager, "organizations", None)
        )
        if self.token_manager is None or self.db is None:
            raise ValueError(
                "FastAPIAuth requires a token_manager and db (pass them "
                "directly or via auth_manager attributes)"
            )
        self._bearer = HTTPBearer(auto_error=False)

    # -- authentication ------------------------------------------------------

    async def _authenticate_token(self, token: str) -> Dict[str, Any]:
        """Validate an access token and load the user; raises 401 errors."""
        try:
            payload = self.token_manager.validate_token(token, expected_type="access")
        except TokenError as exc:
            raise AuthenticationError(exc.message, code=exc.code) from exc
        user = await self.db.get_user_by_id(payload["sub"])
        if user is None or not user.get("is_active", True):
            raise AuthenticationError("Invalid credentials", code="token_invalid")
        return user

    async def require_auth(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(
            HTTPBearer(auto_error=False)
        ),
    ) -> Dict[str, Any]:
        """Dependency requiring a valid bearer access token (401 otherwise)."""
        if credentials is None or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            return await self._authenticate_token(credentials.credentials)
        except TesseraError as exc:
            raise tessera_error_to_http_exception(exc) from exc

    async def optional_auth(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(
            HTTPBearer(auto_error=False)
        ),
    ) -> Optional[Dict[str, Any]]:
        """Dependency returning the user when authenticated, else ``None``."""
        if credentials is None or not credentials.credentials:
            return None
        try:
            return await self._authenticate_token(credentials.credentials)
        except TesseraError:
            return None

    # -- authorization ---------------------------------------------------------

    def require_role(self, *roles: str):
        """Dependency factory requiring one of ``roles``.

        When an ``X-Organization-ID`` header is present and an
        organizations manager is configured, the organization membership
        role is checked instead of the global user role.
        """

        async def role_checker(
            request: Request,
            user: Dict[str, Any] = Depends(self.require_auth),
        ) -> Dict[str, Any]:
            org_id = request.headers.get("X-Organization-ID")
            if org_id and self.organizations is not None:
                org_role = await self.organizations.get_member_role(org_id, user["id"])
                if org_role is None or org_role.value not in roles:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Insufficient permissions",
                    )
                return user
            if user.get("role") not in roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions",
                )
            return user

        return role_checker

    def require_org_membership(self):
        """Dependency factory requiring membership in the org from the header."""

        async def org_checker(
            request: Request,
            user: Dict[str, Any] = Depends(self.require_auth),
        ) -> Dict[str, Any]:
            if self.organizations is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Organizations not configured",
                )
            org_id = request.headers.get("X-Organization-ID")
            if not org_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="X-Organization-ID header required",
                )
            org = await self.organizations.get_organization(org_id)
            if org is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Organization not found",
                )
            role = await self.organizations.get_member_role(org_id, user["id"])
            if role is None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not a member of this organization",
                )
            enriched = dict(user)
            enriched["current_org"] = {
                "id": org["id"],
                "name": org.get("name"),
                "role": role.value,
            }
            return enriched

        return org_checker

    # -- rate limiting ------------------------------------------------------------

    def rate_limit(self, max_requests: int, window_seconds: int):
        """Dependency factory: fixed-window rate limit per client IP + path.

        Uses cache counters under the §3.1 ``tessera:ratelimit:`` namespace.
        Requires ``cache`` to be configured.
        """
        if max_requests <= 0 or window_seconds <= 0:
            raise ValueError("max_requests and window_seconds must be positive")

        async def limiter(request: Request) -> bool:
            if self.cache is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Cache not configured for rate limiting",
                )
            client_ip = request.client.host if request.client else "unknown"
            key = _RATE_LIMIT_KEY_TEMPLATE.format(
                identifier=f"{client_ip}:{request.url.path}"
            )
            try:
                count = await self.cache.incr(key)
                if count == 1:
                    await self.cache.expire(key, window_seconds)
                elif await self.cache.ttl(key) == -1:
                    await self.cache.expire(key, window_seconds)
            except TesseraError as exc:
                raise tessera_error_to_http_exception(exc) from exc
            if count > max_requests:
                remaining = await self.cache.ttl(key)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded",
                    headers={"Retry-After": str(max(1, remaining))},
                )
            return True

        return limiter
