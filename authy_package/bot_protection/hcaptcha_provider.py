"""
hCaptcha Provider Implementation for Authy Package.

Enterprise-grade hCaptcha integration with async support, risk scoring, and comprehensive error handling.

Configuration:
    Option 1 - Direct initialization:
        provider = hCaptchaProvider(
            secret_key="your_secret_key",
            site_key="your_site_key"
        )
    
    Option 2 - Environment variables (recommended):
        # Set these in your .env or environment
        HCAPTCHA_SECRET_KEY=your_secret_key
        HCAPTCHA_SITE_KEY=your_site_key
        
        provider = hCaptchaProvider.from_env()

Usage:
    result = await provider.verify_token(
        token="captcha_response_token",
        remote_ip="192.168.1.1"
    )
    
    if result.success and result.is_human:
        print("Human verified!")
    else:
        print(f"Verification failed: {result.error_codes}")
"""

import os
from typing import Optional, Dict, Any, List
import asyncio
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
class hCaptchaConfig:
    """hCaptcha configuration."""
    secret_key: str
    site_key: str
    verify_url: str = "https://hcaptcha.com/siteverify"
    timeout_seconds: float = 5.0
    
    @classmethod
    def from_env(cls) -> 'hCaptchaConfig':
        """Load configuration from environment variables."""
        secret_key = os.getenv("HCAPTCHA_SECRET_KEY")
        site_key = os.getenv("HCAPTCHA_SITE_KEY")
        
        if not secret_key or not site_key:
            raise ValueError(
                "hCaptcha configuration missing. Set HCAPTCHA_SECRET_KEY and HCAPTCHA_SITE_KEY"
            )
        
        return cls(secret_key=secret_key, site_key=site_key)


class hCaptchaProvider(AbstractCaptchaProvider):
    """
    hCaptcha provider implementation.
    
    Features:
    - Async HTTP requests with httpx
    - Risk score interpretation
    - Comprehensive error handling
    - Timeout configuration
    - Support for enterprise features
    """
    
    def __init__(
        self,
        secret_key: Optional[str] = None,
        site_key: Optional[str] = None,
        verify_url: Optional[str] = None,
        timeout_seconds: float = 5.0,
        risk_thresholds: Optional[Dict[str, float]] = None
    ):
        """
        Initialize hCaptcha provider.
        
        :param secret_key: hCaptcha secret key
        :param site_key: hCaptcha site key
        :param verify_url: Verification endpoint URL (default: hCaptcha's)
        :param timeout_seconds: Request timeout in seconds
        :param risk_thresholds: Custom thresholds for risk levels
        """
        if not HTTPX_AVAILABLE:
            raise ImportError(
                "httpx library not installed. Install with: pip install httpx"
            )
        
        # Load from config or environment
        if secret_key and site_key:
            self.config = hCaptchaConfig(
                secret_key=secret_key,
                site_key=site_key,
                verify_url=verify_url or hCaptchaConfig.verify_url,
                timeout_seconds=timeout_seconds
            )
        else:
            self.config = hCaptchaConfig.from_env()
            if verify_url:
                self.config.verify_url = verify_url
            self.config.timeout_seconds = timeout_seconds
        
        self._client: Optional[httpx.AsyncClient] = None
        
        # Default risk thresholds (can be customized based on your needs)
        self.risk_thresholds = risk_thresholds or {
            "low": 0.3,
            "medium": 0.7,
            "high": 0.9
        }
    
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
        return "hCaptcha"
    
    @property
    def site_key(self) -> str:
        """Return site key."""
        return self.config.site_key
    
    def _interpret_risk_score(self, score: float) -> RiskLevel:
        """Interpret hCaptcha score into risk level."""
        if score >= self.risk_thresholds["high"]:
            return RiskLevel.CRITICAL
        elif score >= self.risk_thresholds["medium"]:
            return RiskLevel.HIGH
        elif score >= self.risk_thresholds["low"]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    async def verify_token(
        self,
        token: str,
        remote_ip: Optional[str] = None
    ) -> CaptchaVerificationResult:
        """
        Verify an hCaptcha token.
        
        :param token: The hCaptcha response token from frontend widget
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
            
            # Calculate risk score (hCaptcha doesn't provide explicit score,
            # so we infer from other factors)
            risk_score = 0.0
            if not success:
                risk_score = 0.9
            elif error_codes:
                risk_score = 0.5 + (len(error_codes) * 0.1)
            
            # Determine if human based on success and errors
            is_human = success and not error_codes
            
            return CaptchaVerificationResult(
                success=success,
                is_human=is_human,
                risk_score=risk_score,
                risk_level=self._interpret_risk_score(risk_score),
                error_codes=error_codes,
                challenge_ts=challenge_ts,
                hostname=hostname,
                raw_response=result_data
            )
            
        except httpx.TimeoutException as e:
            raise BotProtectionError(f"hCaptcha verification timeout: {str(e)}")
        except httpx.HTTPError as e:
            raise BotProtectionError(f"hCaptcha HTTP error: {str(e)}")
        except Exception as e:
            raise BotProtectionError(f"hCaptcha verification failed: {str(e)}")
    
    async def close(self):
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
    
    @classmethod
    def from_env(cls, **kwargs) -> 'hCaptchaProvider':
        """
        Create hCaptchaProvider from environment variables.
        
        :param kwargs: Additional arguments to override environment values
        :return: Configured hCaptchaProvider instance
        """
        config = hCaptchaConfig.from_env()
        return cls(
            secret_key=kwargs.get('secret_key', config.secret_key),
            site_key=kwargs.get('site_key', config.site_key),
            verify_url=kwargs.get('verify_url', config.verify_url),
            timeout_seconds=kwargs.get('timeout_seconds', config.timeout_seconds),
        )
