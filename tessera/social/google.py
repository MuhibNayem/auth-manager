"""Google OAuth provider client (redirect-based authorization code flow).

Fixes in this revision:

- The ``InstalledAppFlow`` stdin/print loop is gone. This is a pure
  redirect-based authorization-code flow:
  :meth:`GoogleManager.create_authorization_url` returns the URL (with a
  real random ``state``) and :meth:`GoogleManager.exchange_code` exchanges
  the callback code.
- Token refresh uses ``google-auth`` (no hand-rolled HTTP + print-based
  error handling).
- HTTP responses are status-checked and surfaced as :class:`ProviderError`.
"""

from __future__ import annotations

import hmac
import logging
import secrets
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode

import requests

from tessera.errors import ProviderError

logger = logging.getLogger("tessera.social.google")

__all__ = ["GoogleManager"]

_AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_URI = "https://oauth2.googleapis.com/token"
_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
_DEFAULT_SCOPES = ["openid", "email", "profile"]


class GoogleManager:
    """Google OAuth 2.0 redirect flow client."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: Optional[List[str]] = None,
    ):
        if not client_id or not client_secret or not redirect_uri:
            raise ValueError(
                "GoogleManager requires client_id, client_secret and redirect_uri"
            )
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = list(scopes or _DEFAULT_SCOPES)
        self._flow = None

    # -- state -----------------------------------------------------------------

    def generate_state(self) -> str:
        return secrets.token_urlsafe(16)

    @staticmethod
    def validate_state(expected: Optional[str], received: Optional[str]) -> bool:
        if expected is None or received is None:
            return False
        return hmac.compare_digest(
            str(expected).encode("utf-8"), str(received).encode("utf-8")
        )

    # -- redirect flow -----------------------------------------------------------

    def _client_config(self) -> Dict[str, object]:
        return {
            "web": {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "auth_uri": _AUTH_URI,
                "token_uri": _TOKEN_URI,
                "redirect_uris": [self.redirect_uri],
            }
        }

    def create_authorization_url(
        self, state: Optional[str] = None
    ) -> Tuple[str, str]:
        """Build the authorization URL; returns ``(url, state)``.

        No stdin, no printing: the caller redirects the user to the URL
        and receives the code on ``redirect_uri``.
        """
        from google_auth_oauthlib.flow import Flow

        state = state or self.generate_state()
        flow = Flow.from_client_config(
            self._client_config(), scopes=self.scopes, redirect_uri=self.redirect_uri
        )
        authorization_url, flow_state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            state=state,
            prompt="select_account",
        )
        self._flow = flow
        return authorization_url, flow_state

    def exchange_code(self, code: str) -> Dict[str, object]:
        """Exchange the callback code for tokens.

        Returns a dict with ``access_token``, ``refresh_token``,
        ``expires_in`` and ``id_token`` (when present).
        """
        if not code:
            raise ValueError("code is required")
        if self._flow is None:
            raise ValueError(
                "Call create_authorization_url() before exchange_code() so the "
                "flow state is established"
            )
        try:
            self._flow.fetch_token(code=code)
        except Exception as exc:
            raise ProviderError(
                f"Google token exchange failed: {exc}",
                code="google_token_exchange_failed",
            ) from exc
        credentials = self._flow.credentials
        expires_in: Optional[int] = None
        if credentials.expiry is not None:
            from datetime import datetime, timezone

            expires_in = max(
                0, int((credentials.expiry - datetime.now(timezone.utc)).total_seconds())
            )
        return {
            "access_token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "id_token": getattr(credentials, "id_token", None),
            "expires_in": expires_in,
        }

    def refresh_access_token(self, refresh_token: str) -> Dict[str, object]:
        """Refresh via google-auth (real refresh, no manual HTTP)."""
        if not refresh_token:
            raise ValueError("refresh_token is required")
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials

        credentials = Credentials(
            token=None,
            refresh_token=refresh_token,
            token_uri=_TOKEN_URI,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )
        try:
            credentials.refresh(Request())
        except Exception as exc:
            raise ProviderError(
                f"Google token refresh failed: {exc}",
                code="google_token_refresh_failed",
            ) from exc

        expires_in: Optional[int] = None
        if credentials.expiry is not None:
            from datetime import datetime, timezone

            expires_in = max(
                0, int((credentials.expiry - datetime.now(timezone.utc)).total_seconds())
            )
        return {
            "access_token": credentials.token,
            "refresh_token": refresh_token,
            "id_token": getattr(credentials, "id_token", None),
            "expires_in": expires_in,
        }

    # -- profile ---------------------------------------------------------------------

    def get_user_info(self, access_token: str) -> Dict[str, object]:
        """Fetch the userinfo document (includes ``email_verified``)."""
        response = requests.get(
            _USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        )
        if response.status_code != 200:
            raise ProviderError(
                f"Google user info failed with status {response.status_code}",
                code="google_user_info_failed",
            )
        payload = response.json()
        if payload.get("error"):
            raise ProviderError(
                f"Google user info error: {payload['error'].get('message')}",
                code="google_user_info_error",
            )
        return payload
