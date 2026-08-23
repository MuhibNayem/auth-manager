"""Django integration adapter (CONTRACTS.md §10).

- Provides ``require_auth``, ``require_role``, ``rate_limit`` and
  ``optional_auth`` — the same names/behavior as the FastAPI and Flask
  adapters.
- Authenticated users are attached to ``request.authy_user`` (dict).
  ``request.user`` is NEVER clobbered.
- ``DjangoAuthMiddleware`` resolves bearer tokens into ``request.authy_user``
  and LOGS + PROPAGATES authentication errors (no bare ``except: pass``).
- Django/asgiref imports are lazy (§0.9).
"""

from __future__ import annotations

import logging
from functools import wraps
from typing import Any, Callable, Dict, Optional

from authy_package.errors import (
    AuthenticationError,
    AuthyError,
    RateLimitError,
    TokenError,
)

logger = logging.getLogger("authy.frameworks.django")

__all__ = [
    "DjangoAuth",
    "DjangoAuthMiddleware",
    "set_auth_manager",
    "get_auth_manager",
]

#: Rate-limit cache key (§3.1 schema).
_RATE_LIMIT_KEY_TEMPLATE = "authy:ratelimit:http:{identifier}"

#: Module-level registry so the middleware can find the auth stack without
#: importing app settings. Set via :func:`set_auth_manager` at startup.
_AUTH_MANAGER: Optional[Any] = None


def set_auth_manager(auth_manager: Any) -> None:
    """Register the auth stack used by :class:`DjangoAuthMiddleware`."""
    global _AUTH_MANAGER
    _AUTH_MANAGER = auth_manager


def get_auth_manager() -> Optional[Any]:
    """Return the registered auth stack (or ``None``)."""
    return _AUTH_MANAGER


def _resolve_components(source: Any) -> Dict[str, Any]:
    """Extract db/cache/token_manager/organizations from an auth stack."""
    return {
        "db": getattr(source, "db", None),
        "cache": getattr(source, "cache", None),
        "token_manager": (
            getattr(source, "token_manager", None)
            or getattr(source, "jwt_manager", None)
        ),
        "organizations": getattr(source, "organizations", None),
    }


def _status_for_error(exc: AuthyError) -> int:
    """HTTP status for an AuthyError (§1 mapping)."""
    if isinstance(exc, (AuthenticationError, TokenError)):
        return 401
    if isinstance(exc, RateLimitError):
        return 429
    from authy_package.errors import AuthorizationError, NotFoundError, ProviderError

    if isinstance(exc, AuthorizationError):
        return 403
    if isinstance(exc, NotFoundError):
        return 404
    if isinstance(exc, ProviderError):
        return 502
    return 500


class DjangoAuth:
    """Django authentication adapter.

    Usage::

        django_auth = DjangoAuth(auth)  # or DjangoAuth(db=..., token_manager=...)

        @django_auth.require_auth
        def protected(request):
            return JsonResponse({"user": request.authy_user})

        @django_auth.require_role("admin")
        def admin_view(request):
            ...
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
        resolved = _resolve_components(auth_manager) if auth_manager else {}
        self.auth_manager = auth_manager
        self.db = db if db is not None else resolved.get("db")
        self.cache = cache if cache is not None else resolved.get("cache")
        self.token_manager = (
            token_manager if token_manager is not None else resolved.get("token_manager")
        )
        self.organizations = (
            organizations if organizations is not None else resolved.get("organizations")
        )
        if self.token_manager is None or self.db is None:
            raise ValueError(
                "DjangoAuth requires a token_manager and db (pass them "
                "directly or via auth_manager attributes)"
            )

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _json_response(data: Dict[str, Any], status_code: int):
        from django.http import JsonResponse  # lazy import (§0.9)

        return JsonResponse(data, status=status_code)

    @staticmethod
    def _token_from_request(request: Any) -> Optional[str]:
        header = request.META.get("HTTP_AUTHORIZATION", "")
        if header.startswith("Bearer "):
            return header[7:].strip()
        return None

    def _authenticate(self, token: str) -> Dict[str, Any]:
        """Validate the bearer token and load the user.

        Raises AuthyError subclasses on failure (callers map to responses).
        """
        from asgiref.sync import async_to_sync  # lazy import (§0.9)

        payload = self.token_manager.validate_token(token, expected_type="access")
        user = async_to_sync(self.db.get_user_by_id)(payload["sub"])
        if user is None or not user.get("is_active", True):
            raise AuthenticationError("Invalid credentials", code="token_invalid")
        return user

    # -- decorators -------------------------------------------------------------

    def require_auth(self, view_func: Callable) -> Callable:
        """Decorator requiring authentication; sets ``request.authy_user``.

        ``request.user`` is left untouched.
        """

        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            token = self._token_from_request(request)
            if not token:
                return self._json_response(
                    {"error": "authentication_failed", "message": "Not authenticated"},
                    401,
                )
            try:
                user = self._authenticate(token)
            except AuthyError as exc:
                logger.info("Django require_auth rejected: %s", exc.code)
                return self._json_response(
                    {"error": exc.code, "message": "Authentication failed"},
                    _status_for_error(exc),
                )
            except Exception:  # noqa: BLE001 - never leak internals
                logger.exception("Django require_auth unexpected error")
                return self._json_response(
                    {"error": "server_error", "message": "Internal server error"}, 500
                )
            request.authy_user = user
            return view_func(request, *args, **kwargs)

        return wrapper

    def require_role(self, *roles: str) -> Callable:
        """Decorator factory requiring one of ``roles`` (org-aware)."""

        def decorator(view_func: Callable) -> Callable:
            @wraps(view_func)
            def wrapper(request, *args, **kwargs):
                user = getattr(request, "authy_user", None)
                if user is None:
                    return self._json_response(
                        {
                            "error": "authentication_failed",
                            "message": "Authentication required",
                        },
                        401,
                    )
                org_id = request.META.get("HTTP_X_ORGANIZATION_ID")
                try:
                    if org_id and self.organizations is not None:
                        from asgiref.sync import async_to_sync

                        org_role = async_to_sync(
                            self.organizations.get_member_role
                        )(org_id, user["id"])
                        if org_role is None or org_role.value not in roles:
                            return self._json_response(
                                {
                                    "error": "authorization_failed",
                                    "message": "Insufficient permissions",
                                },
                                403,
                            )
                    elif user.get("role") not in roles:
                        return self._json_response(
                            {
                                "error": "authorization_failed",
                                "message": "Insufficient permissions",
                            },
                            403,
                        )
                except AuthyError as exc:
                    logger.warning("Django require_role error: %s", exc.code)
                    return self._json_response(
                        {"error": exc.code, "message": "Authorization check failed"},
                        _status_for_error(exc),
                    )
                return view_func(request, *args, **kwargs)

            return wrapper

        return decorator

    def optional_auth(self, view_func: Callable) -> Callable:
        """Decorator setting ``request.authy_user`` when a valid token exists."""

        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            request.authy_user = None
            token = self._token_from_request(request)
            if token:
                try:
                    request.authy_user = self._authenticate(token)
                except AuthyError as exc:
                    logger.debug("Django optional_auth ignored token: %s", exc.code)
            return view_func(request, *args, **kwargs)

        return wrapper

    def rate_limit(self, max_requests: int, window_seconds: int) -> Callable:
        """Decorator factory: fixed-window limit per client IP + path."""
        if max_requests <= 0 or window_seconds <= 0:
            raise ValueError("max_requests and window_seconds must be positive")

        def decorator(view_func: Callable) -> Callable:
            @wraps(view_func)
            def wrapper(request, *args, **kwargs):
                if self.cache is None:
                    return self._json_response(
                        {"error": "server_error", "message": "Rate limiting unavailable"},
                        503,
                    )
                from asgiref.sync import async_to_sync

                client_ip = request.META.get("REMOTE_ADDR", "unknown")
                key = _RATE_LIMIT_KEY_TEMPLATE.format(
                    identifier=f"{client_ip}:{request.path}"
                )
                try:
                    count = async_to_sync(self.cache.incr)(key)
                    if count == 1:
                        async_to_sync(self.cache.expire)(key, window_seconds)
                    elif async_to_sync(self.cache.ttl)(key) == -1:
                        async_to_sync(self.cache.expire)(key, window_seconds)
                except AuthyError as exc:
                    return self._json_response(
                        {"error": exc.code, "message": "Rate limit check failed"},
                        _status_for_error(exc),
                    )
                if count > max_requests:
                    return self._json_response(
                        {"error": "rate_limited", "message": "Rate limit exceeded"},
                        429,
                    )
                return view_func(request, *args, **kwargs)

            return wrapper

        return decorator


class DjangoAuthMiddleware:
    """Middleware resolving bearer tokens into ``request.authy_user``.

    Authentication errors are LOGGED and PROPAGATED (never swallowed).
    Requests without an Authorization header pass through unauthenticated.
    """

    def __init__(self, get_response: Callable) -> None:
        self.get_response = get_response

    def __call__(self, request):
        auth_manager = _AUTH_MANAGER
        header = request.META.get("HTTP_AUTHORIZATION", "")
        request.authy_user = None
        if header.startswith("Bearer "):
            if auth_manager is None:
                logger.error(
                    "DjangoAuthMiddleware received a bearer token but no "
                    "auth manager is registered; call "
                    "authy_package.frameworks.django_adapter.set_auth_manager()"
                )
                raise AuthenticationError(
                    "Authentication backend not configured",
                    code="auth_backend_missing",
                )
            components = _resolve_components(auth_manager)
            token_manager = components["token_manager"]
            db = components["db"]
            if token_manager is None or db is None:
                logger.error("DjangoAuthMiddleware auth manager lacks token_manager/db")
                raise AuthenticationError(
                    "Authentication backend misconfigured",
                    code="auth_backend_invalid",
                )
            token = header[7:].strip()
            try:
                payload = token_manager.validate_token(token, expected_type="access")
                from asgiref.sync import async_to_sync

                user = async_to_sync(db.get_user_by_id)(payload["sub"])
            except TokenError as exc:
                logger.info("Django middleware rejected token: %s", exc.code)
                raise
            if user is None or not user.get("is_active", True):
                logger.info("Django middleware: token subject unknown or inactive")
                raise AuthenticationError(
                    "Invalid credentials", code="token_invalid"
                )
            request.authy_user = user
        response = self.get_response(request)
        return response
