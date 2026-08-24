"""GitHub OAuth provider client.

Fixes in this revision:

- Real random ``state`` generation (``secrets.token_urlsafe``) with a
  constant-time validation hook (CSRF protection).
- HTTP status codes are checked and in-body ``error`` fields from GitHub
  are surfaced as :class:`ProviderError`.
- ``get_primary_email`` resolves the user's primary *verified* email from
  ``/user/emails`` (the profile email may be private/unverified).
"""

from __future__ import annotations

import hmac
import logging
import secrets
from typing import Dict, Optional, Tuple

import requests

from tessera.errors import ProviderError

logger = logging.getLogger("tessera.social.github")

__all__ = ["GitHubManager"]

_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
_TOKEN_URL = "https://github.com/login/oauth/access_token"
_USER_URL = "https://api.github.com/user"
_EMAILS_URL = "https://api.github.com/user/emails"


class GitHubManager:
    """GitHub OAuth 2.0 authorization-code client."""

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        if not client_id or not client_secret or not redirect_uri:
            raise ValueError(
                "GitHubManager requires client_id, client_secret and redirect_uri"
            )
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    # -- state -----------------------------------------------------------------

    def generate_state(self) -> str:
        """Cryptographically random OAuth state parameter."""
        return secrets.token_urlsafe(16)

    def get_authorization_url(
        self, state: Optional[str] = None
    ) -> Tuple[str, str]:
        """Build the authorization URL; returns ``(url, state)``."""
        state = state or self.generate_state()
        from urllib.parse import urlencode

        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "read:user user:email",
            "state": state,
        }
        return f"{_AUTHORIZE_URL}?{urlencode(params)}", state

    @staticmethod
    def validate_state(expected: Optional[str], received: Optional[str]) -> bool:
        """Constant-time CSRF state comparison hook."""
        if expected is None or received is None:
            return False
        return hmac.compare_digest(
            str(expected).encode("utf-8"), str(received).encode("utf-8")
        )

    # -- token exchange -----------------------------------------------------------

    def get_access_token(self, code: str) -> Dict[str, str]:
        """Exchange the authorization code for an access token.

        Raises:
            ProviderError: On HTTP failure or an in-body ``error``.
        """
        if not code:
            raise ValueError("code is required")
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        response = requests.post(
            _TOKEN_URL, data=data, headers={"Accept": "application/json"}, timeout=15
        )
        if response.status_code != 200:
            raise ProviderError(
                f"GitHub token exchange failed with status {response.status_code}",
                code="github_token_exchange_failed",
            )
        payload = response.json()
        if payload.get("error"):
            raise ProviderError(
                f"GitHub token exchange error: {payload.get('error_description') or payload['error']}",
                code="github_token_exchange_error",
            )
        if not payload.get("access_token"):
            raise ProviderError(
                "GitHub token response is missing access_token",
                code="github_token_missing",
            )
        return payload

    # -- profile ---------------------------------------------------------------------

    def get_user_info(self, access_token: str) -> Dict[str, object]:
        """Fetch the authenticated user's profile."""
        response = requests.get(
            _USER_URL,
            headers={"Authorization": f"token {access_token}"},
            timeout=15,
        )
        if response.status_code != 200:
            raise ProviderError(
                f"GitHub user info failed with status {response.status_code}",
                code="github_user_info_failed",
            )
        payload = response.json()
        if payload.get("error"):
            raise ProviderError(
                f"GitHub user info error: {payload.get('message') or payload['error']}",
                code="github_user_info_error",
            )
        return payload

    def get_primary_email(self, access_token: str) -> Optional[Tuple[str, bool]]:
        """Resolve the user's primary email and its verified flag.

        Returns ``(email, verified)`` or ``None`` when the endpoint is
        unavailable / no email exists.
        """
        response = requests.get(
            _EMAILS_URL,
            headers={"Authorization": f"token {access_token}"},
            timeout=15,
        )
        if response.status_code != 200:
            logger.warning(
                "GitHub /user/emails returned status %s", response.status_code
            )
            return None
        try:
            emails = response.json()
        except ValueError:
            return None
        if not isinstance(emails, list) or not emails:
            return None
        primary = next((e for e in emails if e.get("primary")), None)
        chosen = primary or emails[0]
        email = chosen.get("email")
        if not email:
            return None
        return str(email), bool(chosen.get("verified", False))
