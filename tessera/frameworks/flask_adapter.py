"""Flask integration adapter (CONTRACTS.md §10).

- ONE module-level asyncio event loop is reused across all requests;
  coroutines run through ``loop.run_until_complete`` guarded by a lock so
  concurrent Flask worker threads never drive the loop simultaneously.
- Error responses NEVER leak raw exception text; only stable error codes
  and generic messages are returned.
- Decorator names/behavior match the FastAPI and Django adapters:
  ``require_auth``, ``require_role``, ``optional_auth``, ``rate_limit``.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from functools import wraps
from typing import Any, Callable, Dict, Optional

from flask import g, jsonify, request

from tessera.errors import TesseraError, RateLimitError, TokenError

logger = logging.getLogger("tessera.frameworks.flask")

__all__ = ["FlaskAuth", "run_async", "shared_loop"]

#: Rate-limit cache key (§3.1 schema).
_RATE_LIMIT_KEY_TEMPLATE = "tessera:ratelimit:http:{identifier}"

#: Single module-level event loop shared by every request in this worker.
_LOOP_LOCK = threading.Lock()
_LOOP: Optional[asyncio.AbstractEventLoop] = None


def shared_loop() -> asyncio.AbstractEventLoop:
    """Return (and lazily create) the process-wide event loop."""
    global _LOOP
    with _LOOP_LOCK:
        if _LOOP is None or _LOOP.is_closed():
            _LOOP = asyncio.new_event_loop()
        return _LOOP


def run_async(coro):
    """Run a coroutine on the shared loop, thread-safely (lock-guarded)."""
    loop = shared_loop()
    with _LOOP_LOCK:
        return loop.run_until_complete(coro)


def _error_response(code: str, message: str, status_code: int):
    """Uniform JSON error body; never includes raw exception details."""
    return jsonify({"error": code, "message": message}), status_code


def _map_tessera_error(exc: TesseraError):
    """Map TesseraError subclasses to (code, message, status)."""
    if isinstance(exc, RateLimitError):
        return "rate_limited", "Rate limit exceeded", 429
    from tessera.errors import (
        AuthenticationError,
        AuthorizationError,
        NotFoundError,
        ProviderError,
    )

    if isinstance(exc, (AuthenticationError, TokenError)):
        return exc.code or "authentication_failed", "Authentication failed", 401
    if isinstance(exc, AuthorizationError):
        return "authorization_failed", "Insufficient permissions", 403
    if isinstance(exc, NotFoundError):
        return "not_found", "Resource not found", 404
    if isinstance(exc, ProviderError):
        return "provider_error", "Upstream provider error", 502
    return "server_error", "Internal server error", 500


class FlaskAuth:
    """Flask authentication adapter.

    Usage::

        flask_auth = FlaskAuth(db=db, cache=cache, token_manager=jm)

        @app.route('/protected')
        @flask_auth.require_auth
        def protected():
            return jsonify(user=g.current_user)

        @app.route('/admin')
        @flask_auth.require_role('admin')
        def admin():
            return jsonify(message='Admin access')
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
                "FlaskAuth requires a token_manager and db (pass them "
                "directly or via auth_manager attributes)"
            )

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _token_from_request() -> Optional[str]:
        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return header[7:].strip()
        return None

    def _authenticate(self, token: str) -> Dict[str, Any]:
        """Validate the token and load the user (runs async bits on the loop)."""
        payload = self.token_manager.validate_token(token, expected_type="access")
        user = run_async(self.db.get_user_by_id(payload["sub"]))
        if user is None or not user.get("is_active", True):
            from tessera.errors import AuthenticationError

            raise AuthenticationError("Invalid credentials", code="token_invalid")
        return user

    # -- decorators ------------------------------------------------------------

    def require_auth(self, view: Callable) -> Callable:
        """Decorator requiring a valid bearer token; sets ``g.current_user``."""

        @wraps(view)
        def decorated(*args, **kwargs):
            token = self._token_from_request()
            if not token:
                return _error_response(
                    "authentication_failed", "Not authenticated", 401
                )
            try:
                user = self._authenticate(token)
            except TesseraError as exc:
                logger.info("Flask require_auth rejected: %s", exc.code)
                return _error_response(*_map_tessera_error(exc))
            except Exception:  # noqa: BLE001 - never leak internals
                logger.exception("Flask require_auth unexpected error")
                return _error_response("server_error", "Internal server error", 500)
            g.current_user = user
            return view(*args, **kwargs)

        return decorated

    def require_role(self, *roles: str) -> Callable:
        """Decorator factory requiring one of ``roles`` (org-aware)."""

        def decorator(view: Callable) -> Callable:
            @wraps(view)
            def decorated(*args, **kwargs):
                user = getattr(g, "current_user", None)
                if user is None:
                    return _error_response(
                        "authentication_failed", "Authentication required", 401
                    )
                org_id = request.headers.get("X-Organization-ID")
                try:
                    if org_id and self.organizations is not None:
                        org_role = run_async(
                            self.organizations.get_member_role(org_id, user["id"])
                        )
                        if org_role is None or org_role.value not in roles:
                            return _error_response(
                                "authorization_failed",
                                "Insufficient permissions",
                                403,
                            )
                    elif user.get("role") not in roles:
                        return _error_response(
                            "authorization_failed", "Insufficient permissions", 403
                        )
                except TesseraError as exc:
                    return _error_response(*_map_tessera_error(exc))
                return view(*args, **kwargs)

            return decorated

        return decorator

    def optional_auth(self, view: Callable) -> Callable:
        """Decorator setting ``g.current_user`` when a valid token is present."""

        @wraps(view)
        def decorated(*args, **kwargs):
            token = self._token_from_request()
            g.current_user = None
            if token:
                try:
                    g.current_user = self._authenticate(token)
                except (TesseraError, Exception):  # noqa: BLE001 - optional path
                    logger.debug("Flask optional_auth: token not accepted")
                    g.current_user = None
            return view(*args, **kwargs)

        return decorated

    def rate_limit(self, max_requests: int, window_seconds: int) -> Callable:
        """Decorator factory: fixed-window limit per client IP + path (cache)."""
        if max_requests <= 0 or window_seconds <= 0:
            raise ValueError("max_requests and window_seconds must be positive")

        def decorator(view: Callable) -> Callable:
            @wraps(view)
            def decorated(*args, **kwargs):
                if self.cache is None:
                    return _error_response(
                        "server_error", "Rate limiting unavailable", 503
                    )
                client_ip = request.remote_addr or "unknown"
                key = _RATE_LIMIT_KEY_TEMPLATE.format(
                    identifier=f"{client_ip}:{request.path}"
                )
                try:
                    count = run_async(self.cache.incr(key))
                    if count == 1:
                        run_async(self.cache.expire(key, window_seconds))
                    elif run_async(self.cache.ttl(key)) == -1:
                        run_async(self.cache.expire(key, window_seconds))
                except TesseraError as exc:
                    return _error_response(*_map_tessera_error(exc))
                if count > max_requests:
                    return _error_response(
                        "rate_limited", "Rate limit exceeded", 429
                    )
                return view(*args, **kwargs)

            return decorated

        return decorator
