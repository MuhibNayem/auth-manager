"""OpenID Connect (OIDC) client (hardened).

Fixes in this revision:

- ``state`` is ALWAYS generated, stored, validated and consumed
  (single-use); ``nonce`` is generated, stored, validated against the ID
  token and deleted on use. The constructor raises :class:`ConfigError`
  when neither a cache nor a db adapter is provided (there would be
  nowhere to store them).
- base64url decoding uses the correct padding idiom
  (``"=" * (-len(s) % 4)``).
- JWKS is force-refreshed exactly once when a ``kid`` is unknown.
- ``client_secret_basic`` token-endpoint authentication is implemented;
  PKCE is mandatory for public clients (no client secret).
- ``azp`` is enforced when the audience claim is a list with more than
  one entry.
- Cached tokens are keyed by the sha256 of the full token, never a
  truncated prefix.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urljoin

import jwt

from tessera.errors import AuthenticationError, ConfigError, ProviderError

logger = logging.getLogger("tessera.oidc")

__all__ = ["OIDCConfig", "OIDCManager"]

#: §3.1-style cache key templates.
STATE_KEY_TEMPLATE = "tessera:oauth:state:{state}"
NONCE_KEY_TEMPLATE = "tessera:oauth:nonce:{nonce}"
TOKEN_CACHE_KEY_TEMPLATE = "tessera:oidc:tokens:{token_hash}"
#: db settings fallback key for state storage.
STATE_SETTING_TEMPLATE = "tessera_oidc_state:{state}"

STATE_TTL_SECONDS = 600


def _b64url_decode(value: str) -> bytes:
    """base64url decode with the correct padding idiom."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class OIDCConfig:
    """Configuration for an OIDC relying-party client."""

    def __init__(
        self,
        client_id: str,
        client_secret: Optional[str],
        redirect_uri: str,
        issuer: Optional[str] = None,
        authorization_endpoint: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        userinfo_endpoint: Optional[str] = None,
        jwks_uri: Optional[str] = None,
        end_session_endpoint: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        response_type: str = "code",
        token_endpoint_auth_method: str = "client_secret_post",
        require_pkce: bool = True,
        clock_skew_seconds: int = 60,
    ):
        if not client_id or not redirect_uri:
            raise ValueError("client_id and redirect_uri are required")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.issuer = issuer
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self.jwks_uri = jwks_uri
        self.end_session_endpoint = end_session_endpoint
        self.scopes = scopes or ["openid", "profile", "email"]
        self.response_type = response_type
        self.token_endpoint_auth_method = token_endpoint_auth_method
        self.require_pkce = require_pkce
        self.clock_skew_seconds = clock_skew_seconds

        self._jwks_cache: Optional[Dict[str, Any]] = None
        self._jwks_cache_time: Optional[float] = None

    @property
    def is_public_client(self) -> bool:
        """Public clients (no secret) MUST use PKCE."""
        return not self.client_secret

    async def discover(self) -> "OIDCConfig":
        """Populate endpoints from the issuer's discovery document."""
        if not self.issuer:
            raise ValueError("Issuer URL is required for discovery")
        import aiohttp

        discovery_url = urljoin(self.issuer, ".well-known/openid-configuration")
        async with aiohttp.ClientSession() as session:
            async with session.get(discovery_url) as response:
                if response.status != 200:
                    raise ProviderError(
                        f"Discovery failed: {response.status}", code="oidc_discovery_failed"
                    )
                config = await response.json()

        self.authorization_endpoint = self.authorization_endpoint or config.get(
            "authorization_endpoint"
        )
        self.token_endpoint = self.token_endpoint or config.get("token_endpoint")
        self.userinfo_endpoint = self.userinfo_endpoint or config.get("userinfo_endpoint")
        self.jwks_uri = self.jwks_uri or config.get("jwks_uri")
        self.end_session_endpoint = self.end_session_endpoint or config.get(
            "end_session_endpoint"
        )
        if not all([self.authorization_endpoint, self.token_endpoint, self.jwks_uri]):
            raise ValueError("Missing required OIDC endpoints after discovery")
        return self

    async def get_jwks(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Fetch the provider JWKS (1h cache; force refresh on unknown kid)."""
        import aiohttp

        now = time.time()
        if (
            not force_refresh
            and self._jwks_cache
            and self._jwks_cache_time
            and (now - self._jwks_cache_time) < 3600
        ):
            return self._jwks_cache
        if not self.jwks_uri:
            raise ValueError("JWKS URI not configured")

        async with aiohttp.ClientSession() as session:
            async with session.get(self.jwks_uri) as response:
                if response.status != 200:
                    raise ProviderError(
                        f"Failed to fetch JWKS: {response.status}",
                        code="oidc_jwks_fetch_failed",
                    )
                self._jwks_cache = await response.json()
                self._jwks_cache_time = now
        return self._jwks_cache


class OIDCManager:
    """OIDC authorization-code client with PKCE, state and nonce."""

    def __init__(self, config: OIDCConfig, database: Any = None, cache: Any = None):
        if config is None:
            raise ConfigError("OIDCManager requires an OIDCConfig")
        if database is None and cache is None:
            raise ConfigError(
                "OIDCManager requires at least one of a cache or database "
                "adapter to store state/nonce securely"
            )
        self.config = config
        self.db = database
        self.cache = cache

    # -- state / nonce storage --------------------------------------------------

    async def _save_pending_state(self, record: Dict[str, Any]) -> None:
        state = record["state"]
        if self.cache is not None:
            await self.cache.set_json(
                STATE_KEY_TEMPLATE.format(state=state),
                record,
                ttl_seconds=STATE_TTL_SECONDS,
            )
        else:
            await self.db.set_setting(STATE_SETTING_TEMPLATE.format(state=state), record)

    async def _consume_pending_state(self, state: str) -> Optional[Dict[str, Any]]:
        """Fetch-and-delete the pending state record (single use)."""
        record: Optional[Dict[str, Any]] = None
        if self.cache is not None:
            key = STATE_KEY_TEMPLATE.format(state=state)
            record = await self.cache.get_json(key)
            if record is not None:
                await self.cache.delete(key)
        else:
            setting_key = STATE_SETTING_TEMPLATE.format(state=state)
            record = await self.db.get_setting(setting_key)
            if record is not None:
                await self.db.set_setting(setting_key, None)
        return record if isinstance(record, dict) else None

    async def _consume_nonce(self, nonce: str) -> None:
        """Delete a nonce key after it has been verified (§3.1)."""
        if self.cache is not None:
            await self.cache.delete(NONCE_KEY_TEMPLATE.format(nonce=nonce))

    # -- PKCE -----------------------------------------------------------------------

    def generate_pkce_pair(self) -> Tuple[str, str]:
        """Generate ``(code_verifier, code_challenge)`` (S256)."""
        code_verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return code_verifier, code_challenge

    # -- authorization -----------------------------------------------------------------

    def create_authorization_url(
        self,
        state: Optional[str] = None,
        code_verifier: Optional[str] = None,
        prompt: Optional[str] = None,
        login_hint: Optional[str] = None,
    ) -> Tuple[str, str, str]:
        """Create the authorization URL; returns ``(url, state, verifier)``.

        State is always generated (when absent) and stored together with a
        fresh nonce and the PKCE verifier. PKCE is mandatory for public
        clients.
        """
        if not self.config.authorization_endpoint:
            raise ValueError(
                "OIDC authorization endpoint is not configured. Run provider "
                "discovery or set authorization_endpoint first."
            )
        if not state:
            state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(16)

        pkce_required = self.config.require_pkce or self.config.is_public_client
        if pkce_required:
            if not code_verifier:
                code_verifier, code_challenge = self.generate_pkce_pair()
            else:
                digest = hashlib.sha256(code_verifier.encode()).digest()
                code_challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        else:
            code_challenge = None

        params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "response_type": self.config.response_type,
            "scope": " ".join(self.config.scopes),
            "state": state,
            "nonce": nonce,
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        if prompt:
            params["prompt"] = prompt
        if login_hint:
            params["login_hint"] = login_hint

        authorization_url = f"{self.config.authorization_endpoint}?{urlencode(params)}"

        record: Dict[str, Any] = {
            "state": state,
            "nonce": nonce,
            "created_at": _utcnow().isoformat(),
        }
        if code_verifier:
            record["code_verifier"] = code_verifier

        import asyncio

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self._save_pending_state(record))
        else:
            raise RuntimeError(
                "create_authorization_url() is the sync variant; call "
                "create_authorization_url_async() from async code so state "
                "is stored deterministically"
            )

        return authorization_url, state, code_verifier or ""

    async def create_authorization_url_async(
        self,
        state: Optional[str] = None,
        code_verifier: Optional[str] = None,
        prompt: Optional[str] = None,
        login_hint: Optional[str] = None,
    ) -> Tuple[str, str, str]:
        """Async variant that persists state/nonce without a background task."""
        if not self.config.authorization_endpoint:
            raise ValueError(
                "OIDC authorization endpoint is not configured. Run provider "
                "discovery or set authorization_endpoint first."
            )
        if not state:
            state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(16)

        pkce_required = self.config.require_pkce or self.config.is_public_client
        if pkce_required:
            if not code_verifier:
                code_verifier, code_challenge = self.generate_pkce_pair()
            else:
                digest = hashlib.sha256(code_verifier.encode()).digest()
                code_challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        else:
            code_challenge = None

        params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "response_type": self.config.response_type,
            "scope": " ".join(self.config.scopes),
            "state": state,
            "nonce": nonce,
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        if prompt:
            params["prompt"] = prompt
        if login_hint:
            params["login_hint"] = login_hint

        record: Dict[str, Any] = {
            "state": state,
            "nonce": nonce,
            "created_at": _utcnow().isoformat(),
        }
        if code_verifier:
            record["code_verifier"] = code_verifier
        await self._save_pending_state(record)

        return (
            f"{self.config.authorization_endpoint}?{urlencode(params)}",
            state,
            code_verifier or "",
        )

    # -- token exchange --------------------------------------------------------------

    async def _request_tokens(
        self, data: Dict[str, str], headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """POST the token request (hook method; tests may monkeypatch)."""
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.config.token_endpoint, data=data, headers=headers
            ) as response:
                if response.status != 200:
                    try:
                        error_data = await response.json()
                    except Exception:
                        error_data = await response.text()
                    raise ProviderError(
                        f"Token exchange failed: {error_data}",
                        code="oidc_token_exchange_failed",
                    )
                return await response.json()

    def _build_token_request(self, extra: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Apply the configured token-endpoint auth method."""
        data = dict(extra)
        headers: Dict[str, str] = {}
        method = self.config.token_endpoint_auth_method
        if self.config.client_secret:
            if method == "client_secret_basic":
                raw = f"{self.config.client_id}:{self.config.client_secret}"
                encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
                headers["Authorization"] = f"Basic {encoded}"
                data["client_id"] = self.config.client_id
            else:  # client_secret_post (default)
                data["client_id"] = self.config.client_id
                data["client_secret"] = self.config.client_secret
        else:
            data["client_id"] = self.config.client_id
        return data, headers

    async def exchange_code_for_tokens(
        self,
        code: str,
        state: str,
        code_verifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Exchange the code for tokens after consuming state.

        Raises:
            AuthenticationError: Unknown/consumed state (CSRF or replay).
            ValueError: Missing PKCE verifier when PKCE is required.
        """
        record = await self._consume_pending_state(state)
        if record is None:
            raise AuthenticationError(
                "Invalid or expired state parameter", code="oidc_state_invalid"
            )
        if not hmac.compare_digest(
            str(record.get("state", "")).encode("utf-8"), str(state).encode("utf-8")
        ):
            raise AuthenticationError(
                "State mismatch - possible CSRF attack", code="oidc_state_mismatch"
            )

        pkce_required = self.config.require_pkce or self.config.is_public_client
        if not code_verifier:
            code_verifier = record.get("code_verifier")
        if pkce_required and not code_verifier:
            raise ValueError(
                "PKCE code_verifier is required (mandatory for public clients)"
            )

        if not self.config.token_endpoint:
            raise ValueError(
                "OIDC token endpoint is not configured. Run provider discovery "
                "or set token_endpoint first."
            )

        extra = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.config.redirect_uri,
        }
        if code_verifier:
            extra["code_verifier"] = code_verifier
        data, headers = self._build_token_request(extra)
        tokens = await self._request_tokens(data, headers)

        if "id_token" in tokens:
            await self.validate_id_token(
                tokens["id_token"], expected_nonce=record.get("nonce")
            )
            if record.get("nonce"):
                await self._consume_nonce(record["nonce"])

        if self.cache is not None and tokens.get("access_token"):
            ttl = int(tokens.get("expires_in", 3600)) - 60
            if ttl > 0:
                await self.cache.set_json(
                    TOKEN_CACHE_KEY_TEMPLATE.format(
                        token_hash=_sha256_hex(str(tokens["access_token"]))
                    ),
                    tokens,
                    ttl_seconds=ttl,
                )
        return tokens

    # -- ID token validation --------------------------------------------------------------

    async def _find_jwk(self, kid: Optional[str]) -> Optional[Dict[str, Any]]:
        """Find the JWK for ``kid``, force-refreshing JWKS once on a miss."""
        jwks = await self.config.get_jwks()
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return key
        # Unknown kid: refresh the JWKS exactly once and retry.
        jwks = await self.config.get_jwks(force_refresh=True)
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return key
        return None

    async def validate_id_token(
        self, id_token: str, expected_nonce: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate signature, issuer, audience, nonce and azp."""
        if not self.config.issuer:
            raise ConfigError(
                "OIDC issuer must be configured (run discovery or set issuer) "
                "before validating ID tokens"
            )
        header = jwt.get_unverified_header(id_token)
        kid = header.get("kid")
        jwk = await self._find_jwk(kid)
        if not jwk:
            raise AuthenticationError(
                f"No matching key found for kid: {kid}", code="oidc_kid_not_found"
            )
        public_key = self._jwk_to_public_key(jwk)

        try:
            payload = jwt.decode(
                id_token,
                public_key,
                algorithms=["RS256", "ES256"],
                audience=self.config.client_id,
                issuer=self.config.issuer,
                options={
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
                leeway=self.config.clock_skew_seconds,
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationError("ID token has expired", code="oidc_token_expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthenticationError("ID token audience mismatch", code="oidc_aud_mismatch") from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthenticationError("ID token issuer mismatch", code="oidc_iss_mismatch") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthenticationError(
                f"ID token validation failed: {exc}", code="oidc_token_invalid"
            ) from exc

        # Nonce must match the one generated at authorization time.
        if expected_nonce is not None:
            token_nonce = payload.get("nonce")
            if not token_nonce or not hmac.compare_digest(
                str(token_nonce).encode("utf-8"), str(expected_nonce).encode("utf-8")
            ):
                raise AuthenticationError(
                    "ID token nonce mismatch - possible replay", code="oidc_nonce_mismatch"
                )

        # azp is required when aud is a multi-valued list.
        audience = payload.get("aud")
        if isinstance(audience, list) and len(audience) > 1:
            if payload.get("azp") != self.config.client_id:
                raise AuthenticationError(
                    "ID token azp does not match this client", code="oidc_azp_mismatch"
                )
        return payload

    def _jwk_to_public_key(self, jwk: Dict[str, Any]) -> Any:
        """Convert a JWK to a cryptography public key (correct padding)."""
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1,
            SECP384R1,
            SECP521R1,
            EllipticCurvePublicNumbers,
        )
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

        kty = jwk.get("kty")
        if kty == "RSA":
            n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
            e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
            return RSAPublicNumbers(e, n).public_key()
        if kty == "EC":
            crv = jwk.get("crv")
            x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
            y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
            if crv == "P-256":
                curve = SECP256R1()
            elif crv == "P-384":
                curve = SECP384R1()
            elif crv == "P-521":
                curve = SECP521R1()
            else:
                raise ValueError(f"Unsupported EC curve: {crv}")
            return EllipticCurvePublicNumbers(x, y, curve).public_key()
        raise ValueError(f"Unsupported key type: {kty}")

    # -- userinfo / refresh / logout ------------------------------------------------------

    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        if not self.config.userinfo_endpoint:
            raise ValueError("Userinfo endpoint not configured")
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.get(
                self.config.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            ) as response:
                if response.status != 200:
                    try:
                        error_data = await response.json()
                    except Exception:
                        error_data = await response.text()
                    raise ProviderError(
                        f"Userinfo request failed: {error_data}",
                        code="oidc_userinfo_failed",
                    )
                return await response.json()

    async def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        if not self.config.token_endpoint:
            raise ValueError("Token endpoint not configured")
        extra = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        data, headers = self._build_token_request(extra)
        tokens = await self._request_tokens(data, headers)
        if "id_token" in tokens:
            await self.validate_id_token(tokens["id_token"])
        return tokens

    async def logout(
        self,
        id_token_hint: Optional[str] = None,
        post_logout_redirect_uri: Optional[str] = None,
    ) -> str:
        if not self.config.end_session_endpoint:
            raise ValueError("End session endpoint not configured")
        params: Dict[str, str] = {}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        return f"{self.config.end_session_endpoint}?{urlencode(params)}"

    # -- convenience callback --------------------------------------------------------------

    async def handle_oidc_callback(
        self,
        code: str,
        state: str,
        code_verifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Exchange the code, fetch userinfo and provision the user."""
        tokens = await self.exchange_code_for_tokens(code, state, code_verifier)
        user_info = await self.get_user_info(tokens["access_token"])
        user = await self._provision_user(user_info, tokens)
        return {"user": user, "tokens": tokens, "user_info": user_info}

    async def _provision_user(
        self, user_info: Dict[str, Any], tokens: Dict[str, Any]
    ) -> Dict[str, Any]:
        """JIT provisioning; unverified emails never link existing accounts."""
        email = user_info.get("email")
        if not email:
            raise ValueError("Email not available from OIDC provider")
        email_verified = bool(user_info.get("email_verified", False))

        user = await self.db.get_user_by_identifier(email=email)
        if user:
            if not email_verified:
                raise AuthenticationError(
                    "Provider email is not verified; cannot access an existing account",
                    code="email_unverified",
                )
            return user

        if not email_verified:
            raise AuthenticationError(
                "Cannot create an account from an unverified email",
                code="email_unverified",
            )

        user_data = {
            "email": email,
            "username": user_info.get("preferred_username") or email.split("@")[0],
            "full_name": user_info.get("name"),
            "first_name": user_info.get("given_name"),
            "last_name": user_info.get("family_name"),
            "picture": user_info.get("picture"),
            "locale": user_info.get("locale"),
            "oidc_subject": user_info.get("sub"),
            "issuer": self.config.issuer,
            "auth_method": "oidc",
            "email_verified": True,
        }
        user_data = {k: v for k, v in user_data.items() if v is not None}
        await self.db.create_user(user_data)
        return await self.db.get_user_by_identifier(email=email)
