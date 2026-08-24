"""Security primitives for the Tessera package (CONTRACTS.md §6).

Contents:
- Password hashing with the ``bcrypt`` library directly (passlib is banned
  project-wide); Argon2 via ``argon2-cffi`` when configured.
- :func:`verify_password_constant_time` which always runs a real hash
  comparison (dummy hash when the stored hash is missing) so login timing
  does not reveal whether the account exists.
- :class:`JWTTokenManager` issuing/validating access and refresh tokens with
  claims ``{sub, type, jti, iat, exp, iss?, aud?}``.
- Async rate-limit / lockout helpers backed by cache counters
  (``tessera:ratelimit:login:{identifier}`` / ``tessera:lockout:{identifier}``).
- :class:`SecurityManager` implementing the password-reset flow: tokens from
  :func:`secrets.token_urlsafe`, sha256-hashed at rest under
  ``tessera:reset:{token_hash}``, single-use atomic consume, constant-time
  compare, reset link built from ``config.base_url`` and the raw token never
  included in the email body. Mailjet sending is kept but the client is only
  constructed when keys are present; when email is unconfigured sending is a
  logged no-op so tests never need network.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import bcrypt
import jwt

from tessera.cache.abstract_cache import AbstractCache
from tessera.config import AuthConfig
from tessera.db.abstract_db import AbstractDatabase
from tessera.errors import (
    AuthenticationError,
    ConfigError,
    ProviderError,
    RateLimitError,
    TokenError,
)

logger = logging.getLogger("tessera.utils.security")

__all__ = [
    "hash_password",
    "verify_password",
    "verify_password_constant_time",
    "generate_reset_token",
    "JWTTokenManager",
    "SecurityManager",
    "enforce_login_rate_limit",
    "record_login_failure",
    "clear_login_failures",
    "RESET_TOKEN_CACHE_PREFIX",
    "LOGIN_RATE_LIMIT_KEY_TEMPLATE",
    "LOCKOUT_KEY_TEMPLATE",
]

#: bcrypt only consumes the first 72 bytes of a password.
_BCRYPT_MAX_BYTES = 72

#: Cache key prefix for hashed password-reset tokens (§6).
RESET_TOKEN_CACHE_PREFIX = "tessera:reset:"

#: Cache key templates for login rate limiting / lockout (§3.1).
LOGIN_RATE_LIMIT_KEY_TEMPLATE = "tessera:ratelimit:login:{identifier}"
LOCKOUT_KEY_TEMPLATE = "tessera:lockout:{identifier}"

#: Reserved JWT claims managed by :class:`JWTTokenManager`; callers may not
#: override them via ``additional_claims``.
_RESERVED_CLAIMS = frozenset({"sub", "type", "jti", "iat", "exp", "iss", "aud", "nbf"})

#: Pre-computed bcrypt hash (rounds=12) used as the dummy comparison target
#: when no stored hash exists. Its preimage is irrelevant — it exists purely
#: to equalize verification timing.
_DUMMY_BCRYPT_HASH_ROUNDS_12 = "$2b$12$SCvKAnBnXZyrSk3bxJj/OORL5FwGAjWQfiVMjrRgw4yK5JkLCCqMC"

_dummy_hash_cache: Dict[Tuple[str, int], str] = {
    ("bcrypt", 12): _DUMMY_BCRYPT_HASH_ROUNDS_12
}


# ---------------------------------------------------------------------------
# password hashing
# ---------------------------------------------------------------------------

def _bcrypt_bytes(password: str) -> bytes:
    """Encode a password for bcrypt, truncating to 72 bytes (§6)."""
    encoded = password.encode("utf-8")
    if len(encoded) > _BCRYPT_MAX_BYTES:
        logger.debug("Password exceeds 72 bytes; truncating for bcrypt")
        encoded = encoded[:_BCRYPT_MAX_BYTES]
    return encoded


def _argon2_hasher():
    """Lazily construct the argon2-cffi PasswordHasher (§0.9 lazy imports)."""
    try:
        from argon2 import PasswordHasher
    except ImportError as exc:  # pragma: no cover - exercised only w/o extra
        raise ImportError(
            "argon2 password hashing requires the 'argon2-cffi' package; "
            "install tessera with the corresponding extra"
        ) from exc
    return PasswordHasher()


def hash_password(
    password: str,
    *,
    algorithm: str = "bcrypt",
    bcrypt_rounds: int = 12,
) -> str:
    """Hash a password with the configured algorithm.

    Args:
        password: The plaintext password.
        algorithm: ``"bcrypt"`` (direct bcrypt) or ``"argon2"`` (argon2-cffi).
        bcrypt_rounds: bcrypt cost factor (ignored for argon2).

    Returns:
        The encoded hash string.

    Raises:
        ValueError: On empty input or an unsupported algorithm.
    """
    if not isinstance(password, str) or password == "":
        raise ValueError("password must be a non-empty string")
    if algorithm == "bcrypt":
        salt = bcrypt.gensalt(rounds=bcrypt_rounds)
        return bcrypt.hashpw(_bcrypt_bytes(password), salt).decode("ascii")
    if algorithm == "argon2":
        return _argon2_hasher().hash(password)
    raise ValueError(f"Unsupported password hash algorithm: {algorithm!r}")


def verify_password(candidate: str, hashed: Optional[str]) -> bool:
    """Verify a candidate password against a stored hash.

    Dispatches on the hash prefix (``$2a$/$2b$/$2y$`` -> bcrypt,
    ``$argon2`` -> argon2). Returns ``False`` for malformed input instead of
    raising. Callers handling possibly-missing users should prefer
    :func:`verify_password_constant_time`.
    """
    if not isinstance(candidate, str) or not hashed or not isinstance(hashed, str):
        return False
    if hashed.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            return bcrypt.checkpw(_bcrypt_bytes(candidate), hashed.encode("ascii"))
        except (ValueError, TypeError) as exc:
            logger.debug("bcrypt verification failed: %s", exc)
            return False
    if hashed.startswith("$argon2"):
        try:
            return _argon2_hasher().verify(hashed, candidate)
        except Exception as exc:  # argon2 raises typed exceptions
            logger.debug("argon2 verification failed: %s", exc)
            return False
    logger.debug("Unrecognized password hash format")
    return False


def _get_dummy_hash(algorithm: str, bcrypt_rounds: int) -> str:
    """Return (and cache) a dummy hash for constant-time comparison."""
    key = (algorithm, bcrypt_rounds)
    cached = _dummy_hash_cache.get(key)
    if cached is not None:
        return cached
    # Dummy preimage is random per process; the value only needs to be a
    # valid hash of the right algorithm/cost so timing is equalized.
    dummy = _dummy_hash_cache[key] = hash_password(
        secrets.token_urlsafe(32), algorithm=algorithm, bcrypt_rounds=bcrypt_rounds
    )
    return dummy


def verify_password_constant_time(
    candidate: str,
    hashed_or_None: Optional[str],
    *,
    algorithm: str = "bcrypt",
    bcrypt_rounds: int = 12,
) -> bool:
    """Verify a password, always performing real hashing work.

    When ``hashed_or_None`` is ``None`` (unknown user) the candidate is
    verified against a dummy hash so the code path takes comparable time to a
    real verification; the function then returns ``False`` (§6).

    Args:
        candidate: Plaintext password attempt.
        hashed_or_None: Stored hash, or ``None`` when the user is missing.
        algorithm: Algorithm for the dummy hash (``"bcrypt"`` or ``"argon2"``).
        bcrypt_rounds: Cost factor for the bcrypt dummy hash.
    """
    if hashed_or_None is None:
        dummy = _get_dummy_hash(algorithm, bcrypt_rounds)
        verify_password(candidate if isinstance(candidate, str) else "", dummy)
        return False
    return verify_password(candidate, hashed_or_None)


def generate_reset_token() -> str:
    """Generate a cryptographically secure password-reset token (§6)."""
    return secrets.token_urlsafe(32)


def _hash_reset_token(token: str) -> str:
    """SHA-256 hex digest of a reset token (tokens are hashed at rest)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

class JWTTokenManager:
    """Issues and validates access/refresh JWTs per CONTRACTS.md §6.

    Claims: ``{sub, type: "access"|"refresh", jti, iat, exp, iss?, aud?}``.
    ``validate_token(token, *, expected_type)`` enforces the ``type`` claim
    and raises :class:`TokenError` on any failure.
    """

    ACCESS = "access"
    REFRESH = "refresh"
    _VALID_TYPES = frozenset({ACCESS, REFRESH})

    def __init__(self, config: AuthConfig) -> None:
        if not config.jwt_secret:
            raise ConfigError(
                "JWTTokenManager requires config.jwt_secret to be set; "
                "call AuthConfig.validate() before constructing"
            )
        self._secret: str = config.jwt_secret
        self._algorithm: str = config.jwt_algorithm
        self._access_ttl_seconds: int = config.access_token_ttl_seconds
        self._refresh_ttl_seconds: int = config.refresh_token_ttl_seconds
        self._issuer: Optional[str] = config.jwt_issuer
        self._audience: Optional[str] = config.jwt_audience
        self._leeway_seconds: int = config.jwt_clock_skew_seconds

    # -- issuance ------------------------------------------------------

    def _issue(
        self,
        subject: str,
        token_type: str,
        *,
        ttl_seconds: int,
        jti: Optional[str] = None,
        additional_claims: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, str]:
        """Encode a signed token; returns ``(token, jti)``."""
        if not subject or not isinstance(subject, str):
            raise ValueError("subject must be a non-empty string")
        if jti is not None and (not isinstance(jti, str) or jti == ""):
            raise ValueError("jti must be a non-empty string when provided")
        if additional_claims:
            collisions = _RESERVED_CLAIMS.intersection(additional_claims)
            if collisions:
                raise ValueError(
                    f"additional_claims may not override reserved claims: "
                    f"{sorted(collisions)}"
                )
        now = datetime.now(timezone.utc)
        token_jti = jti or secrets.token_urlsafe(16)
        payload: Dict[str, Any] = {
            "sub": subject,
            "type": token_type,
            "jti": token_jti,
            "iat": now,
            "exp": now + timedelta(seconds=ttl_seconds),
        }
        if self._issuer:
            payload["iss"] = self._issuer
        if self._audience:
            payload["aud"] = self._audience
        if additional_claims:
            payload.update(additional_claims)
        token = jwt.encode(payload, self._secret, algorithm=self._algorithm)
        return token, token_jti

    def create_access_token(
        self,
        user_identifier: str,
        *,
        additional_claims: Optional[Dict[str, Any]] = None,
        jti: Optional[str] = None,
    ) -> str:
        """Create a signed access token for ``user_identifier``."""
        token, _ = self._issue(
            user_identifier,
            self.ACCESS,
            ttl_seconds=self._access_ttl_seconds,
            jti=jti,
            additional_claims=additional_claims,
        )
        return token

    def create_refresh_token(self, user_identifier: str, *, jti: Optional[str] = None) -> str:
        """Create a signed refresh token for ``user_identifier``."""
        token, _ = self._issue(
            user_identifier, self.REFRESH, ttl_seconds=self._refresh_ttl_seconds, jti=jti
        )
        return token

    def create_token_pair(self, user_identifier: str) -> Dict[str, str]:
        """Create an access/refresh token pair.

        Returns a dict with ``access_token``, ``refresh_token`` and their
        ``access_jti`` / ``refresh_jti`` values for the §3.1 cache key schema.
        """
        access_token, access_jti = self._issue(
            user_identifier, self.ACCESS, ttl_seconds=self._access_ttl_seconds
        )
        refresh_token, refresh_jti = self._issue(
            user_identifier, self.REFRESH, ttl_seconds=self._refresh_ttl_seconds
        )
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "access_jti": access_jti,
            "refresh_jti": refresh_jti,
        }

    # -- validation ----------------------------------------------------

    def validate_token(self, token: str, *, expected_type: str) -> Dict[str, Any]:
        """Validate a token and enforce its ``type`` claim.

        Args:
            token: The encoded JWT.
            expected_type: ``"access"`` or ``"refresh"``.

        Returns:
            The decoded claim dict.

        Raises:
            ValueError: If ``expected_type`` is not a known token type.
            TokenError: If the token is expired, invalid, or of the wrong type.
        """
        if expected_type not in self._VALID_TYPES:
            raise ValueError(f"expected_type must be one of {sorted(self._VALID_TYPES)}")
        if not token or not isinstance(token, str):
            raise TokenError("Token is missing", code="token_invalid")
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                options={"require": ["exp", "iat", "sub", "jti"]},
                issuer=self._issuer,
                audience=self._audience,
                leeway=self._leeway_seconds,
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenError("Token has expired", code="token_expired") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise TokenError("Token is missing required claims", code="token_invalid") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenError("Token is invalid", code="token_invalid") from exc

        token_type = payload.get("type")
        if token_type != expected_type:
            raise TokenError(
                f"Expected a {expected_type} token, got {token_type!r}",
                code="token_wrong_type",
            )
        if not payload.get("sub"):
            raise TokenError("Token is missing a subject", code="token_invalid")
        return payload



# ---------------------------------------------------------------------------
# rate limiting / lockout (cache counters, §3.1 keys)
# ---------------------------------------------------------------------------

_NO_CACHE_RATE_LIMIT_WARNED = False


def _warn_rate_limit_no_cache() -> None:
    """Warn once that rate limiting fails open without a cache (review NEW-9)."""
    global _NO_CACHE_RATE_LIMIT_WARNED
    if not _NO_CACHE_RATE_LIMIT_WARNED:
        _NO_CACHE_RATE_LIMIT_WARNED = True
        logger.warning(
            "Login rate limiting is DISABLED: no cache adapter configured "
            "(fails open). Configure a cache to enforce rate limits."
        )


async def enforce_login_rate_limit(
    cache: AbstractCache,
    identifier: str,
    *,
    config: AuthConfig,
) -> None:
    """Pre-check a login attempt against rate-limit and lockout state.

    Args:
        cache: Cache backend holding the §3.1 counters.
        identifier: Normalized login identifier (email/username).
        config: Auth configuration with rate-limit settings.

    Raises:
        ValueError: If ``identifier`` is empty.
        AuthenticationError: If the account is currently locked out.
        RateLimitError: If the attempt budget for the window is exhausted.
    """
    if not identifier or not isinstance(identifier, str):
        raise ValueError("identifier must be a non-empty string")
    if cache is None:
        _warn_rate_limit_no_cache()
        return
    if not config.rate_limit_enabled:
        return

    lockout_key = LOCKOUT_KEY_TEMPLATE.format(identifier=identifier)
    if await cache.exists(lockout_key):
        logger.info("Login attempt blocked: %s is locked out", identifier)
        raise AuthenticationError(
            "Account is temporarily locked due to too many failed login attempts",
            code="account_locked",
        )

    counter_key = LOGIN_RATE_LIMIT_KEY_TEMPLATE.format(identifier=identifier)
    raw_count = await cache.get(counter_key)
    attempts = int(raw_count) if raw_count is not None else 0
    if attempts >= config.rate_limit_max_attempts:
        remaining = await cache.ttl(counter_key)
        if remaining < 0:
            # Defensive: a counter without TTL would lock forever; reset it.
            await cache.expire(counter_key, config.rate_limit_window_seconds)
            remaining = config.rate_limit_window_seconds
        raise RateLimitError(
            "Too many login attempts; please try again later",
            retry_after=max(1, remaining),
        )


async def record_login_failure(
    cache: AbstractCache,
    identifier: str,
    *,
    config: AuthConfig,
) -> None:
    """Count a failed login and engage lockout at the configured threshold.

    The counter lives at ``tessera:ratelimit:login:{identifier}`` with a
    sliding-free fixed window of ``rate_limit_window_seconds``. When the
    failure count reaches ``rate_limit_max_attempts`` a lockout marker is set
    at ``tessera:lockout:{identifier}`` for ``account_lockout_duration_seconds``
    and the failure counter is reset (lockout supersedes rate limiting).
    """
    if not identifier or not isinstance(identifier, str):
        raise ValueError("identifier must be a non-empty string")
    if cache is None:
        _warn_rate_limit_no_cache()
        return
    if not config.rate_limit_enabled:
        return

    counter_key = LOGIN_RATE_LIMIT_KEY_TEMPLATE.format(identifier=identifier)
    attempts = await cache.incr(counter_key)
    if attempts == 1:
        await cache.expire(counter_key, config.rate_limit_window_seconds)
    elif await cache.ttl(counter_key) == -1:
        # Key exists without TTL (e.g. created elsewhere); make it expire.
        await cache.expire(counter_key, config.rate_limit_window_seconds)

    if attempts >= config.rate_limit_max_attempts:
        lockout_key = LOCKOUT_KEY_TEMPLATE.format(identifier=identifier)
        await cache.set(
            lockout_key, "1", ttl_seconds=config.account_lockout_duration_seconds
        )
        await cache.delete(counter_key)
        logger.warning("Account %s locked out after %d failed logins", identifier, attempts)


async def clear_login_failures(
    cache: AbstractCache,
    identifier: str,
    *,
    config: AuthConfig,
) -> None:
    """Clear failure counters and lockout after a successful login."""
    if not identifier or not isinstance(identifier, str):
        raise ValueError("identifier must be a non-empty string")
    if cache is None:
        return
    if not config.rate_limit_enabled:
        return
    await cache.delete(LOGIN_RATE_LIMIT_KEY_TEMPLATE.format(identifier=identifier))
    await cache.delete(LOCKOUT_KEY_TEMPLATE.format(identifier=identifier))


# ---------------------------------------------------------------------------
# email dispatch
# ---------------------------------------------------------------------------

class _EmailDispatcher:
    """Sends email through the configured provider.

    The provider client is constructed lazily and only when credentials are
    present. When email is unconfigured, :meth:`send` is a logged no-op so
    that development and tests never require network access.
    """

    def __init__(self, config: AuthConfig) -> None:
        self._config = config
        self._mailjet_client: Optional[Any] = None

    @property
    def configured(self) -> bool:
        """True when a provider is selected and its credentials are present."""
        cfg = self._config
        if not cfg.email_enabled:
            return False
        if cfg.email_provider == "mailjet":
            return bool(cfg.mailjet_api_key and cfg.mailjet_api_secret)
        if cfg.email_provider == "sendgrid":
            return bool(cfg.sendgrid_api_key)
        if cfg.email_provider == "ses":
            return bool(cfg.ses_access_key_id and cfg.ses_secret_access_key)
        return False

    def _get_mailjet_client(self) -> Any:
        """Construct the Mailjet client once; lazy-import the SDK (§0.9)."""
        if self._mailjet_client is None:
            try:
                from mailjet_rest import Client
            except ImportError as exc:
                raise ProviderError(
                    "Mailjet email sending requires the 'mailjet-rest' package",
                    code="email_sdk_missing",
                ) from exc
            self._mailjet_client = Client(
                auth=(self._config.mailjet_api_key, self._config.mailjet_api_secret),
                version="v3.1",
            )
        return self._mailjet_client

    async def send(
        self,
        *,
        to_email: str,
        subject: str,
        text_body: str,
        html_body: str,
    ) -> Dict[str, Any]:
        """Send an email; no-op with a logged warning when unconfigured.

        Raises:
            ValueError: If ``to_email`` is empty.
            ProviderError: On provider failure or missing SDK.
        """
        if not to_email or not isinstance(to_email, str):
            raise ValueError("to_email must be a non-empty string")
        if not self.configured:
            logger.warning(
                "Email is not configured (email_enabled=%s, provider=%s); "
                "skipping send of '%s' to %s",
                self._config.email_enabled,
                self._config.email_provider,
                subject,
                to_email,
            )
            return {"sent": False, "reason": "email_unconfigured"}

        sender_email = self._config.sender_email or "noreply@localhost"
        sender_name = self._config.sender_name or self._config.app_name
        provider = self._config.email_provider

        if provider == "mailjet":
            client = self._get_mailjet_client()
            data = {
                "Messages": [
                    {
                        "From": {"Email": sender_email, "Name": sender_name},
                        "To": [{"Email": to_email, "Name": ""}],
                        "Subject": subject,
                        "TextPart": text_body,
                        "HTMLPart": html_body,
                    }
                ]
            }
            try:
                response = await asyncio.to_thread(client.send, data=data)
            except Exception as exc:
                raise ProviderError(f"Mailjet send failed: {exc}", code="email_send_failed") from exc
            status_code = getattr(response, "status_code", None)
            if status_code != 200:
                raise ProviderError(
                    f"Mailjet send failed with status {status_code}",
                    code="email_send_failed",
                )
            return {"sent": True, "provider": "mailjet"}

        raise ProviderError(
            f"Email provider {provider!r} is not implemented in this build; "
            "only 'mailjet' sending is currently supported",
            code="email_provider_unsupported",
        )


# ---------------------------------------------------------------------------
# password reset flow
# ---------------------------------------------------------------------------

class SecurityManager:
    """Password-reset orchestration per CONTRACTS.md §6.

    Reset tokens are generated with :func:`secrets.token_urlsafe` and stored
    only as sha256 hashes under ``tessera:reset:{token_hash}``. Tokens are
    single-use (atomic consume), compared in constant time, and the raw token
    never appears in email bodies — only the link built from
    ``config.base_url`` does.
    """

    def __init__(self, db: AbstractDatabase, cache: AbstractCache, config: AuthConfig) -> None:
        self._db = db
        self._cache = cache
        self._config = config
        self._email = _EmailDispatcher(config)

    @property
    def email_configured(self) -> bool:
        """True when outbound email is fully configured."""
        return self._email.configured

    # -- reset request ---------------------------------------------------

    async def request_password_reset(
        self,
        *,
        email: Optional[str] = None,
        username: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Start a password reset for the account matching one identifier.

        The response is identical whether or not the account exists so that
        account enumeration is not possible.
        """
        if not any((email, username, phone)):
            raise ValueError("At least one of email, username or phone is required")

        generic_message = (
            "If an account matches the provided identifier, a password reset "
            "link has been sent."
        )

        user = await self._db.get_user_by_identifier(
            username=username, email=email, phone=phone
        )
        if user is None:
            logger.info("Password reset requested for unknown identifier")
            return {"message": generic_message}

        recipient = user.get("email")
        if not recipient:
            logger.warning(
                "Password reset requested for user %s without an email address",
                user.get("id"),
            )
            return {"message": generic_message}

        reset_token = generate_reset_token()
        token_hash = _hash_reset_token(reset_token)
        record = {
            "user_id": user["id"],
            "email": recipient,
            "token_hash": token_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await self._cache.set(
            RESET_TOKEN_CACHE_PREFIX + token_hash,
            json.dumps(record),
            ttl_seconds=self._config.reset_token_ttl_seconds,
        )

        reset_link = (
            f"{self._config.base_url.rstrip('/')}/auth/reset-password?token={reset_token}"
        )
        text_body = (
            "We received a request to reset your password. Use the link below "
            f"to choose a new one:\n\n{reset_link}\n\nIf you did not request "
            "this, you can ignore this email."
        )
        html_body = (
            "<html><body>"
            "<h2>Password Reset Request</h2>"
            "<p>We received a request to reset your password. Click the button "
            "below to choose a new one:</p>"
            f'<p><a href="{reset_link}">Reset Password</a></p>'
            "<p>If you did not request this, you can ignore this email. Your "
            "password will not change until you create a new one.</p>"
            "</body></html>"
        )
        await self._email.send(
            to_email=recipient,
            subject="Password Reset Request",
            text_body=text_body,
            html_body=html_body,
        )
        logger.info("Password reset link issued for user %s", user.get("id"))
        return {"message": generic_message}

    # -- token validation/consumption -------------------------------------

    def _reset_cache_key(self, token: str) -> str:
        return RESET_TOKEN_CACHE_PREFIX + _hash_reset_token(token)

    async def validate_reset_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Peek at a reset token without consuming it.

        Returns the stored record (``user_id``, ``email``, ...) or ``None``
        when the token is unknown or expired. Comparison is performed in
        constant time against the stored sha256 hash.
        """
        if not token or not isinstance(token, str):
            raise ValueError("token must be a non-empty string")
        raw = await self._cache.get(self._reset_cache_key(token))
        if raw is None:
            return None
        record = json.loads(raw)
        expected_hash = str(record.get("token_hash", ""))
        actual_hash = _hash_reset_token(token)
        if not hmac.compare_digest(
            expected_hash.encode("utf-8"), actual_hash.encode("utf-8")
        ):
            return None
        return record

    async def consume_reset_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Consume a reset token exactly once (atomic get-and-delete).

        Returns the stored record for the caller to act on, or ``None`` when
        the token is unknown, expired, or already consumed.
        """
        if not token or not isinstance(token, str):
            raise ValueError("token must be a non-empty string")
        key = self._reset_cache_key(token)
        raw = await self._cache.get(key)
        if raw is None:
            return None
        record = json.loads(raw)
        expected_hash = str(record.get("token_hash", ""))
        actual_hash = _hash_reset_token(token)
        if not hmac.compare_digest(
            expected_hash.encode("utf-8"), actual_hash.encode("utf-8")
        ):
            return None
        await self._cache.delete(key)
        return record

    # -- password update ---------------------------------------------------

    async def reset_password(self, token: str, new_password: str) -> Dict[str, Any]:
        """Consume a valid reset token and set the new password.

        Also revokes all of the user's sessions when
        ``config.revoke_sessions_on_password_change`` is enabled.

        Raises:
            ValueError: If ``new_password`` is empty.
            AuthenticationError: If the token is invalid, expired or consumed.
        """
        if not new_password or not isinstance(new_password, str):
            raise ValueError("new_password must be a non-empty string")
        record = await self.consume_reset_token(token)
        if record is None:
            raise AuthenticationError(
                "Invalid or expired reset token", code="reset_token_invalid"
            )

        hashed = hash_password(
            new_password,
            algorithm=self._config.password_hash_algorithm,
            bcrypt_rounds=self._config.bcrypt_rounds,
        )
        await self._db.update_user(
            record["user_id"],
            {"hashed_password": hashed, "updated_at": datetime.now(timezone.utc)},
        )

        if self._config.revoke_sessions_on_password_change:
            revoked = await self._db.revoke_all_user_sessions(record["user_id"])
            logger.info(
                "Revoked %d session(s) after password reset for user %s",
                revoked,
                record["user_id"],
            )
        logger.info("Password reset completed for user %s", record["user_id"])
        return {"message": "Password updated successfully."}
