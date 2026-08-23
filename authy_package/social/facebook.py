"""Facebook Login provider client.

Fixes in this revision:

- Real random ``state`` + constant-time validation hook (CSRF protection).
- Token expiry comes from the provider's ``expires_in`` (no hardcoded
  lifetimes).
- ``appsecret_proof`` (HMAC-SHA256 of the access token keyed by the app
  secret) is attached to Graph API calls.
- Access tokens are sent in POST bodies, never in query strings.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode

import requests

from authy_package.errors import ProviderError

logger = logging.getLogger("authy.social.facebook")

__all__ = ["FacebookManager"]

GRAPH_VERSION = "v19.0"
_GRAPH_BASE = f"https://graph.facebook.com/{GRAPH_VERSION}"


class FacebookManager:
    """Facebook OAuth 2.0 authorization-code client."""

    def __init__(self, app_id: str, app_secret: str, redirect_uri: str):
        if not app_id or not app_secret or not redirect_uri:
            raise ValueError(
                "FacebookManager requires app_id, app_secret and redirect_uri"
            )
        self.app_id = app_id
        self.app_secret = app_secret
        self.redirect_uri = redirect_uri

    # -- state -----------------------------------------------------------------

    def generate_state(self) -> str:
        return secrets.token_urlsafe(16)

    def get_authorization_url(
        self, state: Optional[str] = None
    ) -> Tuple[str, str]:
        """Build the dialog URL; returns ``(url, state)``."""
        state = state or self.generate_state()
        params = {
            "client_id": self.app_id,
            "redirect_uri": self.redirect_uri,
            "scope": "email,public_profile",
            "response_type": "code",
            "state": state,
        }
        return f"{_GRAPH_BASE}/dialog/oauth?{urlencode(params)}", state

    @staticmethod
    def validate_state(expected: Optional[str], received: Optional[str]) -> bool:
        if expected is None or received is None:
            return False
        return hmac.compare_digest(
            str(expected).encode("utf-8"), str(received).encode("utf-8")
        )

    def appsecret_proof(self, access_token: str) -> str:
        """HMAC-SHA256 proof binding the access token to the app secret."""
        return hmac.new(
            self.app_secret.encode("utf-8"),
            access_token.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    # -- token exchange -----------------------------------------------------------

    def _apply_expiry(self, access_info: Dict[str, object], fallback_days: int) -> Dict[str, object]:
        """Derive ``expires_at`` from the provider's ``expires_in``."""
        expires_in = access_info.get("expires_in")
        try:
            seconds = int(expires_in)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            seconds = fallback_days * 24 * 3600
        access_info["expires_in"] = seconds
        access_info["expires_at"] = time.time() + seconds
        return access_info

    def get_access_token(self, code: str) -> Dict[str, object]:
        """Exchange the code for a short-lived token (POST body, no query)."""
        if not code:
            raise ValueError("code is required")
        data = {
            "client_id": self.app_id,
            "client_secret": self.app_secret,
            "redirect_uri": self.redirect_uri,
            "code": code,
        }
        response = requests.post(f"{_GRAPH_BASE}/oauth/access_token", data=data, timeout=15)
        if response.status_code != 200:
            raise ProviderError(
                f"Facebook token exchange failed with status {response.status_code}",
                code="facebook_token_exchange_failed",
            )
        payload = response.json()
        if payload.get("error"):
            raise ProviderError(
                f"Facebook token exchange error: {payload['error'].get('message')}",
                code="facebook_token_exchange_error",
            )
        if not payload.get("access_token"):
            raise ProviderError(
                "Facebook token response is missing access_token",
                code="facebook_token_missing",
            )
        return self._apply_expiry(payload, fallback_days=1)

    def get_long_lived_access_token(self, short_lived_token: str) -> Dict[str, object]:
        """Exchange a short-lived token for a long-lived one (~60 days)."""
        data = {
            "grant_type": "fb_exchange_token",
            "client_id": self.app_id,
            "client_secret": self.app_secret,
            "fb_exchange_token": short_lived_token,
        }
        response = requests.post(f"{_GRAPH_BASE}/oauth/access_token", data=data, timeout=15)
        if response.status_code != 200:
            raise ProviderError(
                f"Facebook long-lived token exchange failed with status {response.status_code}",
                code="facebook_token_exchange_failed",
            )
        payload = response.json()
        if payload.get("error"):
            raise ProviderError(
                f"Facebook token exchange error: {payload['error'].get('message')}",
                code="facebook_token_exchange_error",
            )
        return self._apply_expiry(payload, fallback_days=60)

    # -- profile ---------------------------------------------------------------------

    def get_user_info(self, access_token: str) -> Dict[str, object]:
        """Fetch the profile; the token travels in the POST body only."""
        data = {
            "fields": "id,name,email,verified",
            "access_token": access_token,
            "appsecret_proof": self.appsecret_proof(access_token),
        }
        response = requests.post(f"{_GRAPH_BASE}/me", data=data, timeout=15)
        if response.status_code != 200:
            raise ProviderError(
                f"Facebook user info failed with status {response.status_code}",
                code="facebook_user_info_failed",
            )
        payload = response.json()
        if payload.get("error"):
            raise ProviderError(
                f"Facebook user info error: {payload['error'].get('message')}",
                code="facebook_user_info_error",
            )
        return payload

    def logout(self, access_token: str) -> None:
        """Revoke the token (permissions endpoint); token in POST body."""
        data = {
            "access_token": access_token,
            "appsecret_proof": self.appsecret_proof(access_token),
        }
        response = requests.delete(f"{_GRAPH_BASE}/me/permissions", data=data, timeout=15)
        if response.status_code != 200:
            raise ProviderError(
                f"Facebook logout failed with status {response.status_code}",
                code="facebook_logout_failed",
            )

    def is_token_expired(self, access_info: Dict[str, object]) -> bool:
        """True when ``expires_at`` has passed."""
        expires_at = access_info.get("expires_at")
        if expires_at is None:
            return False
        return time.time() >= float(expires_at)  # type: ignore[arg-type]
