"""
Google reCAPTCHA Provider Implementation for Authy Package.

Enterprise-grade reCAPTCHA v2/v3 integration with async support and comprehensive error handling.

Configuration:
    Option 1 - Direct initialization:
        provider = ReCaptchaProvider(
            secret_key="your_secret_key",
            site_key="your_site_key",
            version="v3"  # or "v2"
        )
    
    Option 2 - Environment variables (recommended):
        # Set these in your .env or environment
        RECAPTCHA_SECRET_KEY=your_secret_key
        RECAPTCHA_SITE_KEY=your_site_key
        RECAPTCHA_VERSION=v3
        
        provider = ReCaptchaProvider.from_env()

Usage:
    result = await provider.verify_token(
        token="captcha_response_token",
        remote_ip="192.168.1.1"
    )
    
    if result.success and result.is_human:
        print("Human verified!")
        # For v3, also check score
        if result.risk_score < 0.5:
            print("Low risk user")
"""

import os
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    httpx = None

from .abstract_provider import (
    AbstractCaptchaProvider,
    CaptchaVerificationResult,
    RiskLevel,
    BotProtectionError
)


@dataclass
class ReCaptchaConfig:
    """reCAPTCHA configuration."""
    secret_key: str
    site_key: str
    version: str = "v3"  # "v2" or "v3"
    verify_url: str = "https://www.google.com/recaptcha/api/siteverify"
    timeout_seconds: float = 5.0
    min_score: float = 0.5  # For v3
    
    @classmethod
    def from_env(cls) -> 'ReCaptchaConfig':
        """Load configuration from environment variables."""
        secret_key = os.getenv("RECAPTCHA_SECRET_KEY")
        site_key = os.getenv("RECAPTCHA_SITE_KEY")
        version = os.getenv("RECAPTCHA_VERSION", "v3")
        min_score = float(os.getenv("RECAPTCHA_MIN_SCORE", "0.5"))
        
        if not secret_key or not site_key:
            raise ValueError(
                "reCAPTCHA configuration missing. Set RECAPTCHA_SECRET_KEY and RECAPTCHA_SITE_KEY"
            )
        
        return cls(
            secret_key=secret_key,
            site_key=site_key,
            version=version,
            min_score=min_score
        )


class ReCaptchaProvider(AbstractCaptchaProvider):
    """
    Google reCAPTCHA provider implementation.
    
    Features:
    - Support for both reCAPTCHA v2 and v3
    - Async HTTP requests with httpx
    - Score-based risk assessment (v3)
    - Comprehensive error handling
    - Configurable minimum score threshold
    """
    
    def __init__(
        self,
        secret_key: Optional[str] = None,
        site_key: Optional[str] = None,
        version: Optional[str] = None,
        verify_url: Optional[str] = None,
        timeout_seconds: float = 5.0,
        min_score: Optional[float] = None
    ):
        """
        Initialize reCAPTCHA provider.
        
        :param secret_key: reCAPTCHA secret key
        :param site_key: reCAPTCHA site key
        :param version: reCAPTCHA version ("v2" or "v3")
        :param verify_url: Verification endpoint URL
        :param timeout_seconds: Request timeout in seconds
        :param min_score: Minimum acceptable score for v3 (default: 0.5)
        """
        if not HTTPX_AVAILABLE:
            raise ImportError(
                "httpx library not installed. Install with: pip install httpx"
            )
        
        # Load from config or environment
        if secret_key and site_key:
            self.config = ReCaptchaConfig(
                secret_key=secret_key,
                site_key=site_key,
                version=version or "v3",
                verify_url=verify_url or ReCaptchaConfig.verify_url,
                timeout_seconds=timeout_seconds,
                min_score=min_score or 0.5
            )
        else:
            self.config = ReCaptchaConfig.from_env()
            if version:
                self.config.version = version
            if verify_url:
                self.config.verify_url = verify_url
            if timeout_seconds != 5.0:
                self.config.timeout_seconds = timeout_seconds
            if min_score:
                self.config.min_score = min_score
        
        self._client: Optional[httpx.AsyncClient] = None
    
    async def get_client(self) -> httpx.AsyncClient:
        """Lazily construct the shared async HTTP client.

        This is an async METHOD (not a property): awaiting a coroutine
        returned by a property is a footgun and defeats client caching.
        """
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self.config.timeout_seconds)
        return self._client
    
    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "Google reCAPTCHA"
    
    @property
    def site_key(self) -> str:
        """Return site key."""
        return self.config.site_key
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert reCAPTCHA v3 score to risk level."""
        if score >= 0.9:
            return RiskLevel.LOW
        elif score >= 0.7:
            return RiskLevel.MEDIUM
        elif score >= 0.5:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    async def verify_token(
        self,
        token: str,
        remote_ip: Optional[str] = None
    ) -> CaptchaVerificationResult:
        """
        Verify a reCAPTCHA token.
        
        :param token: The reCAPTCHA response token from frontend widget
        :param remote_ip: Optional IP address for additional validation
        :return: CaptchaVerificationResult with verification status
        """
        try:
            client = await self.get_client()
            
            # Prepare form data
            data = {
                "secret": self.config.secret_key,
                "response": token
            }
            
            if remote_ip:
                data["remoteip"] = remote_ip
            
            # Make verification request
            response = await client.post(self.config.verify_url, data=data)
            response.raise_for_status()
            
            result_data = response.json()
            
            # Parse response
            success = result_data.get("success", False)
            challenge_ts = result_data.get("challenge_ts")
            hostname = result_data.get("hostname")
            error_codes = result_data.get("error-codes", [])
            
            # Handle version-specific fields
            score = result_data.get("score", 1.0)  # v3 only
            action = result_data.get("action")  # v3 only
            
            # For v2, success means human
            # For v3, we need to check score
            if self.config.version == "v3":
                is_human = success and score >= self.config.min_score
                risk_score = 1.0 - score  # Invert: high score = low risk
                risk_level = self._score_to_risk_level(score)
            else:
                # v2 - binary success/failure
                is_human = success
                risk_score = 0.0 if success else 0.9
                risk_level = RiskLevel.LOW if success else RiskLevel.HIGH
            
            return CaptchaVerificationResult(
                success=success,
                is_human=is_human,
                risk_score=risk_score,
                risk_level=risk_level,
                error_codes=error_codes,
                challenge_ts=challenge_ts,
                hostname=hostname,
                raw_response=result_data
            )
            
        except httpx.TimeoutException as e:
            raise BotProtectionError(f"reCAPTCHA verification timeout: {str(e)}")
        except httpx.HTTPError as e:
            raise BotProtectionError(f"reCAPTCHA HTTP error: {str(e)}")
        except Exception as e:
            raise BotProtectionError(f"reCAPTCHA verification failed: {str(e)}")
    
    async def close(self):
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
    
    @classmethod
    def from_env(cls, **kwargs) -> 'ReCaptchaProvider':
        """
        Create ReCaptchaProvider from environment variables.
        
        :param kwargs: Additional arguments to override environment values
        :return: Configured ReCaptchaProvider instance
        """
        config = ReCaptchaConfig.from_env()
        return cls(
            secret_key=kwargs.get('secret_key', config.secret_key),
            site_key=kwargs.get('site_key', config.site_key),
            version=kwargs.get('version', config.version),
            verify_url=kwargs.get('verify_url', config.verify_url),
            timeout_seconds=kwargs.get('timeout_seconds', config.timeout_seconds),
            min_score=kwargs.get('min_score', config.min_score),
        )
