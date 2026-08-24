"""AWS Cognito integration (CONTRACTS.md §0/§1).

Fixes over the legacy module:

- ``authenticate_user`` uses the real **USER_SRP_AUTH** flow (Cognito's
  default for app clients without a secret): a minimal, secrets-safe
  SRP-6a implementation computes the PASSWORD_VERIFIER challenge response.
  No plaintext-password auth flow is used.
- ``exchange_code_for_tokens`` performs a REAL POST to the user pool's
  hosted-UI ``/oauth2/token`` endpoint (form body; HTTP Basic auth when a
  client secret is configured) instead of the invalid
  ``AUTHORIZATION_CODE`` InitiateAuth call.
- All URL query strings are built with ``urllib.parse.urlencode``.
- All failures raise :class:`tessera.errors.TesseraError` subclasses —
  never ``{"Error": str(e)}`` dicts.
- TOTP MFA: associate the software token FIRST, then set the preference.
- ``boto3`` is imported lazily/optionally (§0.9).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import httpx

from tessera.errors import (
    AuthenticationError,
    ProviderError,
    RateLimitError,
)

try:  # boto3 is optional (§0.9)
    import boto3
    from botocore.exceptions import ClientError

    BOTO3_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    boto3 = None  # type: ignore[assignment]
    ClientError = None  # type: ignore[assignment]
    BOTO3_AVAILABLE = False

logger = logging.getLogger("tessera.cognito")

__all__ = ["CognitoManager", "BOTO3_AVAILABLE"]

#: Seconds for hosted-UI HTTP calls.
_HTTP_TIMEOUT_SECONDS = 30.0


# ---------------------------------------------------------------------------
# error mapping
# ---------------------------------------------------------------------------

def _snake(code: str) -> str:
    """CamelCase -> snake_case for stable error codes."""
    out = []
    for index, char in enumerate(code):
        if char.isupper() and index > 0:
            out.append("_")
        out.append(char.lower())
    return "".join(out)


def _raise_cognito_error(exc: Exception, context: str) -> None:
    """Translate a boto3 ClientError into an TesseraError subclass."""
    response = getattr(exc, "response", None) or {}
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    code = str(error.get("Code", "unknown"))
    message = str(error.get("Message", "Cognito request failed"))
    if code in ("TooManyRequestsException", "LimitExceededException"):
        raise RateLimitError(
            f"{context}: {message}", retry_after=60, code=_snake(code)
        ) from exc
    if code in (
        "NotAuthorizedException",
        "UserNotFoundException",
        "UserNotConfirmedException",
        "ExpiredCodeException",
        "CodeMismatchException",
        "PasswordResetRequiredException",
        "InvalidPasswordException",
    ):
        raise AuthenticationError(f"{context}: {message}", code=_snake(code)) from exc
    raise ProviderError(f"{context}: {message}", code=_snake(code) or "cognito_error") from exc


# ---------------------------------------------------------------------------
# minimal Cognito SRP-6a (RFC 5054 3072-bit group)
# ---------------------------------------------------------------------------

#: RFC 5054 3072-bit MODP group used by Cognito (hex, big-endian).
_N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)

_N = int(_N_HEX, 16)
_G = 2
_HEX_PAD_LENGTH = len(_N_HEX)
_INFO_BITS = b"Caldera Derived Key"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _pad_hex(hex_value: str) -> str:
    """Left-pad a hex string to the group modulus length."""
    return hex_value.rjust(_HEX_PAD_LENGTH, "0")


def _long_to_bytes(value: int) -> bytes:
    """Minimal big-endian encoding of a positive integer."""
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 (extract + expand)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


class _CognitoSRP:
    """One-shot SRP-6a session for Cognito USER_SRP_AUTH."""

    def __init__(
        self,
        client_id: str,
        username: str,
        password: str,
        client_secret: Optional[str] = None,
    ) -> None:
        if not password:
            raise ValueError("password must be a non-empty string")
        self._client_id = client_id
        self._username = username
        self._password = password
        self._client_secret = client_secret
        self._a = int.from_bytes(secrets.token_bytes(16), "big")
        self._big_a = pow(_G, self._a, _N)
        if self._big_a % _N == 0:
            raise AuthenticationError("SRP ephemeral value rejected", code="srp_error")
        self._k = int.from_bytes(
            _sha256(bytes.fromhex(_N_HEX + _pad_hex(format(_G, "x")))), "big"
        )

    def _secret_hash(self, username: str) -> Optional[str]:
        """SECRET_HASH = base64(HMAC_SHA256(secret, username + client_id))."""
        if not self._client_secret:
            return None
        digest = hmac.new(
            self._client_secret.encode("utf-8"),
            (username + self._client_id).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return base64.b64encode(digest).decode("ascii")

    def start_authentication(self) -> Dict[str, str]:
        """InitiateAuth parameters for USER_SRP_AUTH."""
        params = {
            "USERNAME": self._username,
            "SRP_A": format(self._big_a, "x"),
        }
        secret_hash = self._secret_hash(self._username)
        if secret_hash:
            params["SECRET_HASH"] = secret_hash
        return params

    def respond_to_password_verifier(
        self, challenge_parameters: Dict[str, str]
    ) -> Dict[str, str]:
        """Compute PASSWORD_VERIFIER challenge responses.

        Raises:
            AuthenticationError: On malformed/unsafe server values.
        """
        srp_username = challenge_parameters.get("USERNAME", self._username)
        user_id_for_srp = challenge_parameters.get("USER_ID_FOR_SRP", srp_username)
        salt_hex = challenge_parameters.get("SALT")
        secret_b_hex = challenge_parameters.get("SECRET_B")
        secret_block_b64 = challenge_parameters.get("SECRET_BLOCK")
        if not salt_hex or not secret_b_hex or not secret_block_b64:
            raise AuthenticationError(
                "Malformed PASSWORD_VERIFIER challenge", code="srp_challenge_invalid"
            )

        big_b = int(secret_b_hex, 16)
        if big_b % _N == 0:
            raise AuthenticationError("Invalid server ephemeral value", code="srp_error")

        u_value = int.from_bytes(
            _sha256(
                bytes.fromhex(_pad_hex(format(self._big_a, "x")) + _pad_hex(secret_b_hex))
            ),
            "big",
        )
        if u_value == 0:
            raise AuthenticationError("Invalid SRP mixing parameter", code="srp_error")

        username_password_hash = _sha256(
            f"{user_id_for_srp}:{self._password}".encode("utf-8")
        )
        x_value = int.from_bytes(
            _sha256(bytes.fromhex(salt_hex) + username_password_hash), "big"
        )
        g_x = pow(_G, x_value, _N)
        s_value = pow(big_b - self._k * g_x, self._a + u_value * x_value, _N)

        hkdf_key = _hkdf(_long_to_bytes(s_value), _long_to_bytes(u_value), _INFO_BITS, 16)

        timestamp = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
        secret_block = base64.standard_b64decode(secret_block_b64)
        message = (
            srp_username.encode("utf-8") + secret_block + timestamp.encode("utf-8")
        )
        secret_hash = self._secret_hash(srp_username)
        if secret_hash:
            message += secret_hash.encode("utf-8")
        signature = base64.b64encode(
            hmac.new(hkdf_key, message, hashlib.sha256).digest()
        ).decode("ascii")

        responses = {
            "USERNAME": srp_username,
            "PASSWORD_CLAIM_SECRET_BLOCK": secret_block_b64,
            "PASSWORD_CLAIM_SIGNATURE": signature,
            "TIMESTAMP": timestamp,
        }
        if secret_hash:
            responses["SECRET_HASH"] = secret_hash
        return responses


# ---------------------------------------------------------------------------
# manager
# ---------------------------------------------------------------------------

class CognitoManager:
    """AWS Cognito user-pool operations with typed errors.

    Args:
        region_name: AWS region of the user pool.
        user_pool_id: Cognito user pool id.
        app_client_id: App client id.
        client_secret: Optional app-client secret (enables SECRET_HASH and
            HTTP Basic auth on the hosted-UI token endpoint).
    """

    def __init__(
        self,
        region_name: Optional[str],
        user_pool_id: Optional[str],
        app_client_id: Optional[str],
        *,
        client_secret: Optional[str] = None,
    ) -> None:
        if not BOTO3_AVAILABLE:
            raise ImportError(
                "Cognito support requires the 'boto3' package; install "
                "tessera with the corresponding extra"
            )
        if not region_name or not user_pool_id or not app_client_id:
            raise ValueError("region_name, user_pool_id and app_client_id are required")
        self.region_name = region_name
        self.user_pool_id = user_pool_id
        self.app_client_id = app_client_id
        self.client_secret = client_secret
        self.cognito_client = boto3.client("cognito-idp", region_name=region_name)

    # -- helpers -------------------------------------------------------------

    def _hosted_ui_domain(self) -> str:
        return f"https://{self.user_pool_id}.auth.{self.region_name}.amazoncognito.com"

    # -- user lifecycle ---------------------------------------------------------

    def register_user(
        self,
        username: str,
        password: str,
        email: str,
        phone_number: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register a new user in the user pool."""
        user_attributes: List[Dict[str, str]] = [{"Name": "email", "Value": email}]
        if phone_number:
            user_attributes.append({"Name": "phone_number", "Value": phone_number})
        try:
            return self.cognito_client.sign_up(
                ClientId=self.app_client_id,
                Username=username,
                Password=password,
                UserAttributes=user_attributes,
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "sign_up failed")

    def confirm_user_account(self, username: str, confirmation_code: str) -> Dict[str, Any]:
        """Confirm a user account with the sent code."""
        try:
            return self.cognito_client.confirm_sign_up(
                ClientId=self.app_client_id,
                Username=username,
                ConfirmationCode=confirmation_code,
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "confirm_sign_up failed")

    # -- authentication --------------------------------------------------------

    def authenticate_user(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate via USER_SRP_AUTH (no plaintext password flow).

        Returns Cognito's ``AuthenticationResult`` (access/id/refresh
        tokens), or raises an :class:`AuthenticationError` subclass.
        """
        srp = _CognitoSRP(
            self.app_client_id, username, password, self.client_secret
        )
        try:
            initiate = self.cognito_client.initiate_auth(
                ClientId=self.app_client_id,
                AuthFlow="USER_SRP_AUTH",
                AuthParameters=srp.start_authentication(),
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "initiate_auth failed")
            raise  # unreachable; keeps type-checkers happy

        challenge_name = initiate.get("ChallengeName")
        if challenge_name != "PASSWORD_VERIFIER":
            raise AuthenticationError(
                f"Unexpected challenge during login: {challenge_name}",
                code="challenge_required",
            )
        responses = srp.respond_to_password_verifier(initiate["ChallengeParameters"])
        try:
            final = self.cognito_client.respond_to_auth_challenge(
                ClientId=self.app_client_id,
                ChallengeName="PASSWORD_VERIFIER",
                ChallengeResponses=responses,
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "password verification failed")
            raise  # unreachable
        if final.get("ChallengeName"):
            raise AuthenticationError(
                f"Additional challenge required: {final['ChallengeName']}",
                code="challenge_required",
            )
        return final["AuthenticationResult"]

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh tokens using REFRESH_TOKEN_AUTH."""
        try:
            response = self.cognito_client.initiate_auth(
                ClientId=self.app_client_id,
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters={"REFRESH_TOKEN": refresh_token},
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "refresh_token failed")
            raise  # unreachable
        return response["AuthenticationResult"]

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Fetch the user's attributes with a Cognito access token."""
        try:
            return self.cognito_client.get_user(AccessToken=access_token)
        except ClientError as exc:
            _raise_cognito_error(exc, "get_user failed")
            raise  # unreachable

    # -- hosted UI (social) --------------------------------------------------------

    def initiate_social_login(self, provider: str, redirect_uri: str) -> str:
        """Build the hosted-UI authorize URL (query params urlencoded)."""
        params = {
            "response_type": "code",
            "client_id": self.app_client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "identity_provider": provider,
        }
        return f"{self._hosted_ui_domain()}/oauth2/authorize?" + urlencode(params)

    def exchange_code_for_tokens(
        self, code: str, redirect_uri: str
    ) -> Dict[str, Any]:
        """Exchange an authorization code at the hosted-UI /oauth2/token.

        POSTs the real form-encoded request (HTTP Basic auth when a client
        secret is configured); raises :class:`ProviderError` on failure.
        """
        if not code or not redirect_uri:
            raise ValueError("code and redirect_uri are required")
        data = {
            "grant_type": "authorization_code",
            "client_id": self.app_client_id,
            "code": code,
            "redirect_uri": redirect_uri,
        }
        auth = None
        if self.client_secret:
            auth = httpx.BasicAuth(self.app_client_id, self.client_secret)
        try:
            response = httpx.post(
                f"{self._hosted_ui_domain()}/oauth2/token",
                data=data,
                auth=auth,
                timeout=_HTTP_TIMEOUT_SECONDS,
            )
        except httpx.HTTPError as exc:
            raise ProviderError(
                f"Token exchange request failed: {type(exc).__name__}",
                code="token_exchange_transport_error",
            ) from exc
        if response.status_code != 200:
            raise ProviderError(
                f"Token exchange failed with HTTP {response.status_code}",
                code="token_exchange_failed",
            )
        try:
            return response.json()
        except ValueError as exc:
            raise ProviderError(
                "Token endpoint returned a non-JSON response",
                code="token_exchange_invalid_response",
            ) from exc

    def logout_user(
        self,
        redirect_uri: str,
        access_token: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> Any:
        """Hosted-UI logout URL for social sessions; global sign-out otherwise."""
        if provider:
            if not redirect_uri:
                raise ValueError("Redirect URI must be provided for social logout.")
            params = {"client_id": self.app_client_id, "logout_uri": redirect_uri}
            return f"{self._hosted_ui_domain()}/logout?" + urlencode(params)
        if access_token:
            try:
                self.cognito_client.global_sign_out(AccessToken=access_token)
            except ClientError as exc:
                _raise_cognito_error(exc, "global_sign_out failed")
            return {"message": "User successfully logged out."}
        raise ValueError("Provide an access_token or provider for logout.")

    # -- password reset -----------------------------------------------------------

    def reset_password(self, username: str) -> Dict[str, Any]:
        """Start the forgot-password flow."""
        try:
            return self.cognito_client.forgot_password(
                ClientId=self.app_client_id, Username=username
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "forgot_password failed")
            raise  # unreachable

    def confirm_password(
        self, username: str, confirmation_code: str, new_password: str
    ) -> Dict[str, Any]:
        """Complete the forgot-password flow."""
        try:
            return self.cognito_client.confirm_forgot_password(
                ClientId=self.app_client_id,
                Username=username,
                ConfirmationCode=confirmation_code,
                Password=new_password,
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "confirm_forgot_password failed")
            raise  # unreachable

    # -- MFA -----------------------------------------------------------------------

    def enable_totp_mfa(
        self, username: str, *, user_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """Enable TOTP MFA: associate the token FIRST, then set preference.

        When ``user_code`` is provided it is verified before the
        preference is switched on (Cognito otherwise rejects the change).
        """
        try:
            associate = self.cognito_client.admin_associate_software_token(
                UserPoolId=self.user_pool_id, Username=username
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "associate_software_token failed")
            raise  # unreachable
        session = associate.get("Session")
        if user_code:
            try:
                self.cognito_client.verify_software_token(
                    Session=session, UserCode=user_code
                )
            except ClientError as exc:
                _raise_cognito_error(exc, "verify_software_token failed")
        try:
            self.cognito_client.admin_set_user_mfa_preference(
                UserPoolId=self.user_pool_id,
                Username=username,
                SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "set_user_mfa_preference failed")
        return {
            "secret_code": associate.get("SecretCode"),
            "session": session,
            "message": "TOTP MFA enabled.",
        }

    def enable_sms_mfa(self, username: str) -> Dict[str, Any]:
        """Enable SMS MFA (requires a verified phone number)."""
        try:
            return self.cognito_client.admin_set_user_mfa_preference(
                UserPoolId=self.user_pool_id,
                Username=username,
                SMSMfaSettings={"Enabled": True, "PreferredMfa": True},
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "set_user_mfa_preference failed")
            raise  # unreachable

    def disable_mfa(self, username: str) -> Dict[str, Any]:
        """Disable all MFA options for the user."""
        try:
            return self.cognito_client.admin_set_user_mfa_preference(
                UserPoolId=self.user_pool_id,
                Username=username,
                SMSMfaSettings={"Enabled": False, "PreferredMfa": False},
                SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False},
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "disable_mfa failed")
            raise  # unreachable

    def verify_mfa(self, access_token: str, code: str) -> Dict[str, Any]:
        """Verify a TOTP code against the user's access token."""
        try:
            return self.cognito_client.verify_software_token(
                AccessToken=access_token, UserCode=code
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "verify_software_token failed")
            raise  # unreachable

    def associate_software_token(self, access_token: str) -> str:
        """Start TOTP association; returns the SecretCode for the app."""
        try:
            response = self.cognito_client.associate_software_token(
                AccessToken=access_token
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "associate_software_token failed")
            raise  # unreachable
        return response["SecretCode"]

    # -- attributes -----------------------------------------------------------------

    def update_user_attributes(
        self, username: str, attributes: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """Update arbitrary user attributes (admin API)."""
        try:
            return self.cognito_client.admin_update_user_attributes(
                UserPoolId=self.user_pool_id,
                Username=username,
                UserAttributes=attributes,
            )
        except ClientError as exc:
            _raise_cognito_error(exc, "update_user_attributes failed")
            raise  # unreachable

    def update_user_phone_number(self, username: str, phone_number: str) -> Dict[str, Any]:
        """Update the user's phone number."""
        return self.update_user_attributes(
            username, [{"Name": "phone_number", "Value": phone_number}]
        )

    def update_user_email(self, username: str, email: str) -> Dict[str, Any]:
        """Update the user's email address."""
        return self.update_user_attributes(
            username, [{"Name": "email", "Value": email}]
        )
