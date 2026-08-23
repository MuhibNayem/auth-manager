"""Traditional, Cognito and social authentication flows.

Rewritten against the frozen foundation contracts (CONTRACTS.md §3-§6):

- Login fetches the user, verifies the password with
  :func:`verify_password_constant_time` (dummy hash when the user is
  missing), raises an identical :class:`AuthenticationError` for bad-user
  and bad-password, and enforces rate limiting / lockout via the cache
  counter helpers in ``utils.security``.
- Legacy password hashes (``user["password_algorithm"]`` set) are verified
  and transparently upgraded to bcrypt on first successful login via
  :func:`authy_package.migration.verify_and_upgrade_legacy_hash`.
- The MFA gate requires a valid TOTP code; attempt limiting lives in
  :class:`~authy_package.mfa.mfa_setup.MFAAuthManager`.
- Token pairs come from :class:`JWTTokenManager`; refresh tokens rotate
  through the §3.1 cache ledger (``authy:refresh:{jti}`` deleted on use).
- ``hashed_password`` / ``mfa_secret`` / backup codes are stripped from
  every response.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from authy_package.cache.abstract_cache import AbstractCache
from authy_package.config import AuthConfig
from authy_package.db.abstract_db import AbstractDatabase
from authy_package.errors import (
    AuthenticationError,
    ConfigError,
    RateLimitError,
    TokenError,
)
from authy_package.utils.security import (
    JWTTokenManager,
    SecurityManager,
    clear_login_failures,
    enforce_login_rate_limit,
    hash_password,
    record_login_failure,
    verify_password_constant_time,
)

logger = logging.getLogger("authy.core")

__all__ = ["TraditionalAuthManager", "CognitoAuthManager", "SocialAuthManager"]

#: §3.1 cache key schema.
REFRESH_LEDGER_KEY_TEMPLATE = "authy:refresh:{jti}"
ACCESS_LEDGER_KEY_TEMPLATE = "authy:access:{jti}"
TOKENPAIR_KEY_TEMPLATE = "authy:tokenpair:{user_id}"
SOCIAL_TOKEN_KEY_TEMPLATE = "authy:socialtoken:{user_id}:{provider}"

#: Fields that must never leave the process in an API response.
_SENSITIVE_USER_FIELDS = frozenset(
    {
        "hashed_password",
        "password_hash",
        "legacy_password_hash",
        "mfa_secret",
        "mfa_backup_codes",
        "password_algorithm",
    }
)


def sanitize_user(user: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``user`` without secret-bearing fields."""
    return {key: value for key, value in user.items() if key not in _SENSITIVE_USER_FIELDS}


def _normalize_identifier(
    username: Optional[str], email: Optional[str], phone: Optional[str]
) -> str:
    """Stable rate-limit identifier for one login attempt."""
    if email:
        return str(email).strip().lower()
    if username:
        return str(username).strip().lower()
    if phone:
        return str(phone).strip()
    return ""


async def _begin_mfa_setup(
    mfa_manager: Any,
    *,
    reconfigure: bool,
    username: Optional[str],
    email: Optional[str],
    phone: Optional[str],
) -> Dict[str, Any]:
    """Shared body for enable/reconfigure MFA (single helper, no dup code)."""
    if mfa_manager is None:
        raise ConfigError("MFA manager is not configured")
    if reconfigure:
        return await mfa_manager.reconfigure_mfa(username=username, email=email, phone=phone)
    return await mfa_manager.setup_mfa(username=username, email=email, phone=phone)


class TraditionalAuthManager:
    """Username/password authentication on the db/cache contracts.

    Args:
        db: Database adapter implementing the §4 contract.
        config: The canonical :class:`AuthConfig`.
        cache: Optional cache adapter (§3). Required for rate limiting,
            lockout and refresh-token rotation.
        mfa_manager: Optional :class:`MFAAuthManager`.
        security_manager: Optional :class:`SecurityManager` (reset flow).
        token_manager: Optional pre-built :class:`JWTTokenManager`; built
            from ``config`` when omitted and ``jwt_secret`` is set.
        session_manager: Optional ``SessionManager``; when present, login
            persists sessions via the db contract (save_session/revoke).
    """

    def __init__(
        self,
        db: AbstractDatabase,
        config: AuthConfig,
        cache: Optional[AbstractCache] = None,
        mfa_manager: Any = None,
        security_manager: Optional[SecurityManager] = None,
        token_manager: Optional[JWTTokenManager] = None,
        session_manager: Any = None,
    ) -> None:
        if db is None:
            raise ConfigError("TraditionalAuthManager requires a database adapter")
        if config is None:
            raise ConfigError("TraditionalAuthManager requires an AuthConfig")
        self.db = db
        self.config = config
        self.cache = cache
        self.mfa_manager = mfa_manager
        self.security_manager = security_manager
        self.session_manager = session_manager
        if token_manager is not None:
            self.token_manager: Optional[JWTTokenManager] = token_manager
        elif config.jwt_secret:
            self.token_manager = JWTTokenManager(config)
        else:
            self.token_manager = None

    # -- registration ---------------------------------------------------------

    async def register_user(
        self,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register a new user; the stored hash never appears in responses."""
        if not any((username, email, phone)):
            raise ValueError("At least one of username, email or phone is required")
        if not password or not isinstance(password, str):
            raise ValueError("password must be a non-empty string")

        hashed = hash_password(
            password,
            algorithm=self.config.password_hash_algorithm,
            bcrypt_rounds=self.config.bcrypt_rounds,
        )
        user_data = {
            "username": username,
            "email": email,
            "phone": phone,
            "hashed_password": hashed,
            "mfa_enabled": False,
        }
        created = await self.db.create_user(user_data)
        logger.info("Registered user %s", created.get("id"))
        return {"message": "User registered successfully.", "user": sanitize_user(created)}

    # -- login ------------------------------------------------------------------

    async def _authenticate_password(
        self, user: Optional[Dict[str, Any]], password: str
    ) -> Optional[Dict[str, Any]]:
        """Verify a password, upgrading legacy hashes when configured.

        Returns the (possibly refreshed) user record on success, else None.
        The timing path is equalized for missing users (§6).
        """
        if user is not None and user.get("password_algorithm"):
            from authy_package.migration import verify_and_upgrade_legacy_hash

            upgraded = await verify_and_upgrade_legacy_hash(user, password, self.db)
            if not upgraded:
                return None
            refreshed = await self.db.get_user_by_id(str(user["id"]))
            return refreshed or user

        stored_hash = user.get("hashed_password") if user else None
        valid = verify_password_constant_time(
            password,
            stored_hash,
            algorithm=self.config.password_hash_algorithm,
            bcrypt_rounds=self.config.bcrypt_rounds,
        )
        return user if (valid and user is not None) else None

    async def login_user(
        self,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        password: Optional[str] = None,
        mfa_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Authenticate with password (+ MFA code when MFA is enabled).

        Raises:
            AuthenticationError: Identical error for unknown user and wrong
                password; also raised for lockouts (``account_locked`` code)
                and MFA failures.
            RateLimitError: When the attempt window is exhausted.
        """
        if not password or not isinstance(password, str):
            raise ValueError("password must be a non-empty string")
        identifier = _normalize_identifier(username, email, phone)
        if not identifier:
            raise ValueError("At least one of username, email or phone is required")

        if self.cache is not None:
            await enforce_login_rate_limit(self.cache, identifier, config=self.config)

        user = await self.db.get_user_by_identifier(
            username=username, email=email, phone=phone
        )
        authenticated_user = await self._authenticate_password(user, password)

        if (
            authenticated_user is None
            or not authenticated_user.get("is_active", True)
        ):
            if self.cache is not None:
                await record_login_failure(self.cache, identifier, config=self.config)
            raise AuthenticationError("Invalid credentials", code="authentication_failed")

        # MFA gate -----------------------------------------------------------
        if authenticated_user.get("mfa_enabled") or self.config.mfa_required:
            if not mfa_code:
                raise AuthenticationError(
                    "An MFA code is required to complete login", code="mfa_required"
                )
            if self.mfa_manager is None:
                raise ConfigError("MFA manager is not configured")
            try:
                await self.mfa_manager.verify_mfa_code(
                    mfa_code, username=username, email=email, phone=phone
                )
            except (AuthenticationError, RateLimitError):
                await record_login_failure(self.cache, identifier, config=self.config) if self.cache else None
                raise

        if self.cache is not None:
            await clear_login_failures(self.cache, identifier, config=self.config)

        user_id = str(authenticated_user["id"])
        response: Dict[str, Any] = {
            "message": "Login successful.",
            "user": sanitize_user(authenticated_user),
        }

        tokens = await self._issue_token_pair(user_id)
        if tokens:
            response["access_token"] = tokens["access_token"]
            response["refresh_token"] = tokens["refresh_token"]

        if self.session_manager is not None:
            session = await self.session_manager.create_session(
                user_id, device_info={"auth_method": "password"}
            )
            response["session_id"] = session.id
        return response

    # -- tokens -----------------------------------------------------------------

    async def _issue_token_pair(self, user_id: str) -> Optional[Dict[str, str]]:
        """Issue a JWT pair and record it under the §3.1 cache keys."""
        if self.token_manager is None:
            return None
        tokens = self.token_manager.create_token_pair(user_id)
        if self.cache is not None:
            await self.cache.set(
                REFRESH_LEDGER_KEY_TEMPLATE.format(jti=tokens["refresh_jti"]),
                user_id,
                ttl_seconds=self.config.refresh_token_ttl_seconds,
            )
            await self.cache.set(
                ACCESS_LEDGER_KEY_TEMPLATE.format(jti=tokens["access_jti"]),
                user_id,
                ttl_seconds=self.config.access_token_ttl_seconds,
            )
            await self.cache.set_json(
                TOKENPAIR_KEY_TEMPLATE.format(user_id=user_id),
                {"access_jti": tokens["access_jti"], "refresh_jti": tokens["refresh_jti"]},
                ttl_seconds=self.config.refresh_token_ttl_seconds,
            )
        return tokens

    async def refresh_token(self, refresh_token: str) -> Dict[str, str]:
        """Rotate a refresh token: old jti is deleted, a new pair issued.

        Raises:
            TokenError: When the JWT is invalid/expired/wrong type.
            AuthenticationError: When the jti is unknown to the ledger
                (already rotated or revoked) — replay protection.
        """
        if self.token_manager is None:
            raise ConfigError("JWT is not configured (config.jwt_secret missing)")
        if self.cache is None:
            raise ConfigError("Refresh-token rotation requires a cache adapter")

        payload = self.token_manager.validate_token(
            refresh_token, expected_type=JWTTokenManager.REFRESH
        )
        user_id = str(payload["sub"])
        jti = str(payload["jti"])

        ledger_key = REFRESH_LEDGER_KEY_TEMPLATE.format(jti=jti)
        # §3.1 rotation: delete-then-create; a missing old jti means the
        # token was already rotated or revoked.
        was_present = await self.cache.delete(ledger_key)
        if not was_present:
            raise AuthenticationError(
                "Refresh token has already been used or was revoked",
                code="refresh_token_reused",
            )

        tokens = self.token_manager.create_token_pair(user_id)
        await self.cache.set(
            REFRESH_LEDGER_KEY_TEMPLATE.format(jti=tokens["refresh_jti"]),
            user_id,
            ttl_seconds=self.config.refresh_token_ttl_seconds,
        )
        await self.cache.set(
            ACCESS_LEDGER_KEY_TEMPLATE.format(jti=tokens["access_jti"]),
            user_id,
            ttl_seconds=self.config.access_token_ttl_seconds,
        )
        await self.cache.set_json(
            TOKENPAIR_KEY_TEMPLATE.format(user_id=user_id),
            {"access_jti": tokens["access_jti"], "refresh_jti": tokens["refresh_jti"]},
            ttl_seconds=self.config.refresh_token_ttl_seconds,
        )
        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
        }

    async def logout_user(
        self,
        access_token: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, str]:
        """Invalidate the access-token ledger entry and/or the session."""
        if access_token and self.token_manager is not None:
            try:
                payload = self.token_manager.validate_token(
                    access_token, expected_type=JWTTokenManager.ACCESS
                )
            except TokenError:
                payload = None
            if payload is not None and self.cache is not None:
                await self.cache.delete(
                    ACCESS_LEDGER_KEY_TEMPLATE.format(jti=str(payload["jti"]))
                )
                session_id = session_id or payload.get("session_id")

        if session_id:
            if self.session_manager is not None:
                await self.session_manager.revoke_session(session_id)
            else:
                await self.db.revoke_session(session_id)
        return {"message": "User logged out successfully."}

    # -- MFA (unified helper) --------------------------------------------------

    async def enable_mfa(
        self,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Begin MFA enrollment (pending until the user confirms a code)."""
        user = await self.db.get_user_by_identifier(
            username=username, email=email, phone=phone
        )
        if not user:
            raise AuthenticationError("Invalid credentials", code="authentication_failed")
        if user.get("mfa_enabled"):
            return {"message": "MFA is already enabled for this user."}
        return await _begin_mfa_setup(
            self.mfa_manager,
            reconfigure=False,
            username=username,
            email=email,
            phone=phone,
        )

    async def confirm_mfa(
        self,
        code: str,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Confirm a pending MFA enrollment with a valid TOTP code."""
        if self.mfa_manager is None:
            raise ConfigError("MFA manager is not configured")
        return await self.mfa_manager.confirm_mfa(
            code, username=username, email=email, phone=phone
        )

    async def reconfigure_mfa(
        self,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Rotate the MFA secret (pending until the user confirms a code)."""
        user = await self.db.get_user_by_identifier(
            username=username, email=email, phone=phone
        )
        if not user:
            raise AuthenticationError("Invalid credentials", code="authentication_failed")
        if not user.get("mfa_enabled"):
            raise AuthenticationError(
                "MFA is not enabled for this user", code="mfa_not_enabled"
            )
        return await _begin_mfa_setup(
            self.mfa_manager,
            reconfigure=True,
            username=username,
            email=email,
            phone=phone,
        )

    # -- password reset (delegates to SecurityManager, §6) ----------------------

    async def request_password_reset(
        self,
        email: Optional[str] = None,
        username: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Start a password reset; identical response for unknown accounts."""
        if self.security_manager is None:
            raise ConfigError("Security manager is not configured")
        return await self.security_manager.request_password_reset(
            email=email, username=username, phone=phone
        )

    async def reset_password(self, token: str, new_password: str) -> Dict[str, Any]:
        """Consume a reset token and set the new password."""
        if self.security_manager is None:
            raise ConfigError("Security manager is not configured")
        return await self.security_manager.reset_password(token, new_password)



class CognitoAuthManager:
    """Thin async facade over :class:`CognitoManager` (AWS Cognito).

    The CognitoManager is imported lazily so the core module imports
    cleanly without ``boto3`` installed (§0.9).
    """

    def __init__(self, cognito_manager: Any) -> None:
        if cognito_manager is None:
            raise ConfigError(
                "CognitoAuthManager requires a CognitoManager instance"
            )
        self.cognito_manager = cognito_manager

    async def register_user(
        self, username: str, password: str, email: str, phone_number: Optional[str] = None
    ):
        """Register a new user in the Cognito user pool."""
        return await self.cognito_manager.register_user(
            username, password, email, phone_number
        )

    async def login_user(self, username: str, password: str):
        """Authenticate a user via Cognito."""
        return await self.cognito_manager.authenticate_user(username, password)

    async def logout_user(
        self, redirect_uri: str, access_token: Optional[str] = None, provider: Optional[str] = None
    ):
        """Log the user out (optionally through a social provider)."""
        return await self.cognito_manager.logout_user(redirect_uri, access_token, provider)

    async def refresh_token(self, refresh_token: str):
        """Refresh Cognito tokens."""
        return await self.cognito_manager.refresh_token(refresh_token)

    async def initiate_social_login(self, provider: str, redirect_uri: str):
        """Begin a hosted-UI social login."""
        return await self.cognito_manager.initiate_social_login(provider, redirect_uri)

    async def exchange_code_for_tokens(self, code: str, redirect_uri: str):
        """Exchange a hosted-UI authorization code for tokens."""
        return await self.cognito_manager.exchange_code_for_tokens(code, redirect_uri)

    async def reset_password(self, username: str):
        """Initiate a Cognito password reset."""
        return await self.cognito_manager.reset_password(username)

    async def confirm_password(
        self, username: str, confirmation_code: str, new_password: str
    ):
        """Confirm a new password with the code sent by Cognito."""
        return await self.cognito_manager.confirm_password(
            username, confirmation_code, new_password
        )

    async def confirm_user_account(self, username: str, confirmation_code: str):
        """Confirm a user account with the signup code."""
        return await self.cognito_manager.confirm_user_account(username, confirmation_code)

    async def update_user_attributes(self, access_token: str, attributes: list):
        """Update attributes for the user owning ``access_token``."""
        return await self.cognito_manager.update_user_attributes(access_token, attributes)

    async def update_user_phone_number(self, access_token: str, phone_number: str):
        """Update the phone number of the authenticated user."""
        return await self.cognito_manager.update_user_phone_number(
            access_token, phone_number
        )

    async def update_user_email(self, access_token: str, email: str):
        """Update the email address of the authenticated user."""
        return await self.cognito_manager.update_user_email(access_token, email)

    async def get_user_info(self, access_token: str):
        """Fetch the user's Cognito profile."""
        return await self.cognito_manager.get_user_info(access_token)

    async def enable_TOTP_mfa(self, username: str):
        """Enable TOTP MFA for a user."""
        return await self.cognito_manager.enable_totp_mfa(username)

    async def enable_sms_mfa(self, username: str):
        """Enable SMS MFA for a user."""
        return await self.cognito_manager.enable_sms_mfa(username)

    async def disable_mfa(self, username: str):
        """Disable MFA for a user."""
        return await self.cognito_manager.disable_mfa(username)

    async def verify_mfa(self, access_token: str, code: str):
        """Verify an MFA challenge."""
        return await self.cognito_manager.verify_mfa(access_token, code)

    async def associate_software_token(self, access_token: str):
        """Associate a TOTP software token with the user."""
        return await self.cognito_manager.associate_software_token(access_token)


class SocialAuthManager:
    """Social login orchestration with provider-email-verification checks.

    Security rules enforced for every provider:

    - An **unverified provider email is never linked** to an existing
      account (account-takeover protection): it raises
      :class:`AuthenticationError` with code ``email_unverified``.
    - Accounts are only created from unverified emails when
      ``config.auto_create_users`` is enabled.
    - ``hashed_password`` and other secrets are stripped from responses.

    Args:
        db: Database adapter (§4).
        config: Canonical :class:`AuthConfig` (auto_create_users, JWT).
        cache: Optional cache adapter (§3) for token ledgers.
        token_manager: Optional pre-built :class:`JWTTokenManager`.
        session_manager: Optional ``SessionManager`` (db-backed sessions).
        github_manager / apple_manager / facebook_manager / google_manager:
            Provider clients (see ``authy_package.social``).
    """

    def __init__(
        self,
        db: AbstractDatabase,
        config: AuthConfig,
        cache: Optional[AbstractCache] = None,
        token_manager: Optional[JWTTokenManager] = None,
        session_manager: Any = None,
        github_manager: Any = None,
        apple_manager: Any = None,
        facebook_manager: Any = None,
        google_manager: Any = None,
        mfa_manager: Any = None,
    ) -> None:
        if db is None:
            raise ConfigError("SocialAuthManager requires a database adapter")
        if config is None:
            raise ConfigError("SocialAuthManager requires an AuthConfig")
        self.db = db
        self.config = config
        self.cache = cache
        self.session_manager = session_manager
        self.github_manager = github_manager
        self.apple_manager = apple_manager
        self.facebook_manager = facebook_manager
        self.google_manager = google_manager
        self.mfa_manager = mfa_manager
        if token_manager is not None:
            self.token_manager: Optional[JWTTokenManager] = token_manager
        elif config.jwt_secret:
            self.token_manager = JWTTokenManager(config)
        else:
            self.token_manager = None

    # -- state (CSRF) helpers ---------------------------------------------------

    @staticmethod
    def _check_state(state: Optional[str], expected_state: Optional[str]) -> None:
        """Constant-time CSRF state validation hook."""
        import hmac as _hmac

        if expected_state is None:
            return
        if not state or not _hmac.compare_digest(
            str(state).encode("utf-8"), str(expected_state).encode("utf-8")
        ):
            raise AuthenticationError(
                "OAuth state mismatch - possible CSRF attack", code="oauth_state_mismatch"
            )

    # -- provider login flows ----------------------------------------------------

    async def github_social_login(
        self, code: str, state: Optional[str] = None, expected_state: Optional[str] = None
    ) -> Dict[str, Any]:
        """GitHub authorization-code exchange + login."""
        if self.github_manager is None:
            raise ConfigError("GitHub manager is not configured")
        self._check_state(state, expected_state)

        token_info = await asyncio.to_thread(self.github_manager.get_access_token, code)
        access_token = token_info["access_token"]
        user_info = await asyncio.to_thread(self.github_manager.get_user_info, access_token)

        email = user_info.get("email")
        email_verified = bool(user_info.get("email_verified", False))
        try:
            primary = await asyncio.to_thread(
                self.github_manager.get_primary_email, access_token
            )
        except Exception:  # provider error: fall back to profile email, unverified
            logger.warning("GitHub primary-email lookup failed; treating as unverified")
            primary = None
        if primary:
            email, email_verified = primary
            user_info["email"] = email

        user_info.setdefault("name", user_info.get("login") or email)
        provider_tokens = {
            "access_token": access_token,
            "refresh_token": token_info.get("refresh_token"),
        }
        return await self._handle_social_login(
            "github", user_info, provider_tokens, email_verified=email_verified
        )

    async def facebook_social_login(
        self, code: str, state: Optional[str] = None, expected_state: Optional[str] = None
    ) -> Dict[str, Any]:
        """Facebook code exchange (short -> long-lived token) + login."""
        if self.facebook_manager is None:
            raise ConfigError("Facebook manager is not configured")
        self._check_state(state, expected_state)

        short_lived = await asyncio.to_thread(self.facebook_manager.get_access_token, code)
        long_lived = await asyncio.to_thread(
            self.facebook_manager.get_long_lived_access_token,
            short_lived["access_token"],
        )
        access_token = long_lived["access_token"]
        user_info = await asyncio.to_thread(self.facebook_manager.get_user_info, access_token)

        provider_tokens = {
            "access_token": access_token,
            "expires_in": long_lived.get("expires_in"),
            "expires_at": long_lived.get("expires_at"),
        }
        return await self._handle_social_login(
            "facebook",
            user_info,
            provider_tokens,
            email_verified=bool(user_info.get("verified", False)),
        )

    async def apple_social_login(
        self, redirect_uri: str, code: Optional[str] = None, state: Optional[str] = None
    ) -> Dict[str, Any]:
        """Apple Sign-In; returns the authorization URL when ``code`` is None."""
        if self.apple_manager is None:
            raise ConfigError("Apple manager is not configured")

        if code is None:
            import secrets as _secrets

            auth_state = _secrets.token_urlsafe(16)
            authorization_url = self.apple_manager.get_authorization_url(
                redirect_uri, state=auth_state
            )
            return {"authorization_url": authorization_url, "state": auth_state}

        access_token_info = await self.apple_manager.get_access_token(code)
        user_info = await self.apple_manager.get_user_info(access_token_info["id_token"])
        return await self._handle_social_login(
            "apple",
            user_info,
            access_token_info,
            email_verified=bool(user_info.get("email_verified", False)),
        )

    async def google_social_login(
        self, code: str, state: Optional[str] = None, expected_state: Optional[str] = None
    ) -> Dict[str, Any]:
        """Google redirect-based authorization-code flow + login."""
        if self.google_manager is None:
            raise ConfigError("Google manager is not configured")
        self._check_state(state, expected_state)

        token_info = await asyncio.to_thread(self.google_manager.exchange_code, code)
        user_info = await asyncio.to_thread(
            self.google_manager.get_user_info, token_info["access_token"]
        )
        return await self._handle_social_login(
            "google",
            user_info,
            token_info,
            email_verified=bool(user_info.get("email_verified", False)),
        )

    # -- shared login core ---------------------------------------------------------

    async def _handle_social_login(
        self,
        provider: str,
        user_info: Dict[str, Any],
        access_token_info: Dict[str, Any],
        *,
        email_verified: bool,
    ) -> Dict[str, Any]:
        """Link-or-create the user and issue application tokens.

        Raises:
            AuthenticationError: ``email_unverified`` when an unverified
                provider email would link to an existing account; or when
                no account exists and auto-creation is disabled.
        """
        email = user_info.get("email")
        username = user_info.get("name") or email

        existing_user = None
        if email:
            existing_user = await self.db.get_user_by_identifier(email=email)
        if existing_user is None and username:
            existing_user = await self.db.get_user_by_identifier(username=username)

        if existing_user is not None:
            if not email_verified:
                raise AuthenticationError(
                    "Provider email is not verified; cannot access an existing account",
                    code="email_unverified",
                )
            user = existing_user
        else:
            if not (email_verified or self.config.auto_create_users):
                raise AuthenticationError(
                    "No account exists and automatic account creation is disabled",
                    code="user_not_found",
                )
            user_data = {
                "username": username,
                "email": email,
                "provider": provider,
                "email_verified": bool(email_verified),
                "mfa_enabled": False,
            }
            user = await self.db.create_user(user_data)
            logger.info("Created user %s via %s", user.get("id"), provider)

        user_id = str(user["id"])
        response: Dict[str, Any] = {
            "message": "Login successful.",
            "user": sanitize_user(user),
        }

        if self.token_manager is not None:
            tokens = self.token_manager.create_token_pair(user_id)
            response["access_token"] = tokens["access_token"]
            response["refresh_token"] = tokens["refresh_token"]
            if self.cache is not None:
                await self.cache.set(
                    REFRESH_LEDGER_KEY_TEMPLATE.format(jti=tokens["refresh_jti"]),
                    user_id,
                    ttl_seconds=self.config.refresh_token_ttl_seconds,
                )

        if self.cache is not None and access_token_info.get("access_token"):
            stored = dict(access_token_info)
            stored["stored_at"] = datetime.now(timezone.utc).isoformat()
            await self.cache.set_json(
                SOCIAL_TOKEN_KEY_TEMPLATE.format(user_id=user_id, provider=provider),
                stored,
            )

        if self.session_manager is not None:
            session = await self.session_manager.create_session(
                user_id, device_info={"auth_method": f"social:{provider}"}
            )
            response["session_id"] = session.id
        return response

    # -- provider token refresh / logout ----------------------------------------------

    async def refresh_access_token(
        self, provider: str, refresh_token: str, user: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Refresh the provider access token and update the cached copy."""
        user_id = str(user.get("id", ""))
        if provider == "google" and self.google_manager is not None:
            updated = await asyncio.to_thread(
                self.google_manager.refresh_access_token, refresh_token
            )
        elif provider == "apple" and self.apple_manager is not None:
            updated = await self.apple_manager.refresh_access_token(refresh_token)
        elif provider in ("github", "facebook"):
            raise ValueError(
                f"{provider} issues long-lived tokens; refresh is not supported"
            )
        else:
            raise ValueError(f"Refresh token functionality is not implemented for provider: {provider}")

        if updated and self.cache is not None and user_id:
            stored = dict(updated)
            stored["stored_at"] = datetime.now(timezone.utc).isoformat()
            await self.cache.set_json(
                SOCIAL_TOKEN_KEY_TEMPLATE.format(user_id=user_id, provider=provider),
                stored,
            )
        return updated

    async def logout(self, provider: str, user: Dict[str, Any]) -> Dict[str, str]:
        """Revoke provider tokens where supported and clear the cache entry."""
        user_id = str(user.get("id", ""))
        stored: Dict[str, Any] = {}
        if self.cache is not None and user_id:
            key = SOCIAL_TOKEN_KEY_TEMPLATE.format(user_id=user_id, provider=provider)
            stored = await self.cache.get_json(key) or {}
            access_token = stored.get("access_token")
            if provider == "facebook" and self.facebook_manager is not None and access_token:
                await asyncio.to_thread(self.facebook_manager.logout, access_token)
            elif provider == "apple" and self.apple_manager is not None and access_token:
                await self.apple_manager.logout(access_token)
            await self.cache.delete(key)
        return {"message": "Logout successful."}

    # -- MFA (unified helper, same as traditional flow) --------------------------------

    async def enable_mfa(
        self,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Begin MFA enrollment (pending until the user confirms a code)."""
        user = await self.db.get_user_by_identifier(
            username=username, email=email, phone=phone
        )
        if not user:
            raise AuthenticationError("Invalid credentials", code="authentication_failed")
        if user.get("mfa_enabled"):
            return {"message": "MFA is already enabled for this user."}
        return await _begin_mfa_setup(
            self.mfa_manager,
            reconfigure=False,
            username=username,
            email=email,
            phone=phone,
        )

    async def reconfigure_mfa(
        self,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Rotate the MFA secret (pending until the user confirms a code)."""
        user = await self.db.get_user_by_identifier(
            username=username, email=email, phone=phone
        )
        if not user:
            raise AuthenticationError("Invalid credentials", code="authentication_failed")
        if not user.get("mfa_enabled"):
            raise AuthenticationError(
                "MFA is not enabled for this user", code="mfa_not_enabled"
            )
        return await _begin_mfa_setup(
            self.mfa_manager,
            reconfigure=True,
            username=username,
            email=email,
            phone=phone,
        )
