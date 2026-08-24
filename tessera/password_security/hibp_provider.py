"""Have I Been Pwned (HIBP) password breach checks with k-anonymity.

Privacy: only the first 5 characters of the SHA-1 hash are sent to the
range API; the full password never leaves the process.

Fixes in this revision:

- The ``except httpx.HTTPError`` handler no longer dereferences a possibly
  unbound ``response`` (connection-level failures raised before any
  response existed previously triggered ``UnboundLocalError``).
- :class:`HibpConfig` gains ``fail_closed`` (default ``False``): when the
  breach database is unreachable, fail-closed providers surface the outage
  as a validation failure via
  :class:`~tessera.password_security.password_validator.PasswordSecurityManager`;
  fail-open (default) providers only produce a warning.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from typing import Optional, Tuple

logger = logging.getLogger("tessera.password_security.hibp")

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised without the extra
    HTTPX_AVAILABLE = False
    httpx = None

__all__ = ["HibpConfig", "HibpProvider"]


@dataclass
class HibpConfig:
    """HIBP configuration."""

    api_key: Optional[str] = None
    base_url: str = "https://api.pwnedpasswords.com"
    timeout_seconds: float = 5.0
    use_range_api: bool = True  # k-anonymity range API
    #: When True, an unreachable breach database fails validation closed;
    #: when False (default) the outage is only a warning.
    fail_closed: bool = False

    @classmethod
    def from_env(cls) -> "HibpConfig":
        """Load configuration from environment variables."""
        api_key = os.getenv("HIBP_API_KEY")
        fail_closed = os.getenv("HIBP_FAIL_CLOSED", "").strip().lower() in (
            "true",
            "1",
            "yes",
            "on",
        )
        return cls(api_key=api_key, fail_closed=fail_closed)


class HibpProvider:
    """Have I Been Pwned password breach checker (k-anonymity range API)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout_seconds: float = 5.0,
        fail_closed: bool = False,
    ):
        """Initialize the provider.

        :param api_key: HIBP API key (optional but recommended)
        :param base_url: API base URL
        :param timeout_seconds: Request timeout in seconds
        :param fail_closed: Treat unreachable breach DB as validation failure
        """
        if not HTTPX_AVAILABLE:
            raise ImportError(
                "httpx library not installed. Install with: pip install httpx"
            )

        if api_key:
            self.config = HibpConfig(
                api_key=api_key,
                base_url=base_url or HibpConfig.base_url,
                timeout_seconds=timeout_seconds,
                fail_closed=fail_closed,
            )
        else:
            self.config = HibpConfig.from_env()
            if base_url:
                self.config.base_url = base_url
            self.config.timeout_seconds = timeout_seconds
            # Explicit constructor argument wins over the env-derived default.
            if fail_closed:
                self.config.fail_closed = True

        self._client: Optional["httpx.AsyncClient"] = None

    @property
    async def client(self) -> "httpx.AsyncClient":
        """Lazy initialization of the HTTP client."""
        if self._client is None or self._client.is_closed:
            headers = {}
            if self.config.api_key:
                headers["hibp-api-key"] = self.config.api_key
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout_seconds, headers=headers
            )
        return self._client

    def _hash_password(self, password: str) -> str:
        """SHA-1 hash of the password, upper-cased hex."""
        return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    async def check_password(self, password: str) -> Tuple[bool, int]:
        """Check a password against the breach database.

        :return: Tuple of (is_breached, breach_count)
        :raises Exception: On API/connection errors (callers decide whether
            to fail open or closed).
        """
        sha1_hash = self._hash_password(password)
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        client = await self.client
        url = f"{self.config.base_url}/range/{prefix}"
        response = None
        try:
            response = await client.get(url)

            if response.status_code == 404:
                return False, 0

            response.raise_for_status()

            # Response format: SUFFIX:COUNT per line.
            for line in response.text.strip().split("\n"):
                if ":" in line:
                    hash_suffix, count_str = line.split(":", 1)
                    if hash_suffix.strip().upper() == suffix:
                        count = int(count_str.strip())
                        return count > 0, count
            return False, 0

        except httpx.TimeoutException as e:
            raise Exception(f"HIBP API timeout: {e}") from e
        except httpx.HTTPStatusError as e:
            raise Exception(
                f"HIBP API error: {e.response.status_code} - {e}"
            ) from e
        except httpx.HTTPError as e:
            # Connection-level failure: ``response`` may never have been
            # assigned — never dereference it here.
            status = getattr(response, "status_code", None)
            detail = f"{status} - {e}" if status is not None else str(e)
            raise Exception(f"HIBP API error: {detail}") from e
        except Exception as e:
            raise Exception(f"Failed to check password: {e}") from e

    async def check_password_safe(
        self, password: str
    ) -> Tuple[bool, int, Optional[str]]:
        """Breach check that never raises.

        :return: Tuple of (is_breached, breach_count, error_message)
        """
        try:
            is_breached, count = await self.check_password(password)
            return is_breached, count, None
        except Exception as e:
            if self.config.fail_closed:
                logger.warning("HIBP check failed (fail_closed): %s", e)
            else:
                logger.warning("HIBP check failed (fail-open): %s", e)
            return False, 0, str(e)

    async def get_breach_stats(self) -> Optional[dict]:
        """General breach statistics; ``None`` on any error."""
        client = await self.client
        url = f"{self.config.base_url}/breaches"
        try:
            response = await client.get(url)
            response.raise_for_status()
            breaches = response.json()
            return {
                "total_breaches": len(breaches),
                "total_pastes": None,
                "last_updated": None,
            }
        except Exception:
            return None

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    @classmethod
    def from_env(cls, **kwargs) -> "HibpProvider":
        """Create a provider from environment variables (+ overrides)."""
        config = HibpConfig.from_env()
        return cls(
            api_key=kwargs.get("api_key", config.api_key),
            base_url=kwargs.get("base_url", config.base_url),
            timeout_seconds=kwargs.get("timeout_seconds", config.timeout_seconds),
            fail_closed=kwargs.get("fail_closed", config.fail_closed),
        )
