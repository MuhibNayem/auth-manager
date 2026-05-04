"""
Bot Protection Abstraction Layer for Authy Package.

This module provides a vendor-agnostic interface for CAPTCHA/bot protection providers,
allowing easy integration with hCaptcha, reCAPTCHA, Turnstile, etc.

Usage:
    from authy_package.bot_protection import hCaptchaProvider, BotProtectionManager
    
    # Configure your provider
    provider = hCaptchaProvider.from_env()
    
    # Create bot protection manager
    bot_manager = BotProtectionManager(provider=provider, cache=cache_instance)
    
    # Verify CAPTCHA
    result = await bot_manager.verify_captcha(
        token="captcha_token",
        ip_address="192.168.1.1"
    )
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum
import asyncio


class RiskLevel(Enum):
    """Risk level assessment."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CaptchaVerificationResult:
    """Result of CAPTCHA verification."""
    success: bool
    is_human: bool = True
    risk_score: float = 0.0  # 0.0 to 1.0
    risk_level: RiskLevel = RiskLevel.LOW
    error_codes: List[str] = field(default_factory=list)
    challenge_ts: Optional[str] = None
    hostname: Optional[str] = None
    raw_response: Optional[Dict[str, Any]] = None


@dataclass
class BehavioralAnalysis:
    """Behavioral analysis result."""
    is_suspicious: bool = False
    risk_score: float = 0.0
    flags: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


class AbstractCaptchaProvider(ABC):
    """
    Abstract base class for CAPTCHA providers.
    
    Implement this class to add support for new CAPTCHA providers.
    """
    
    @abstractmethod
    async def verify_token(self, token: str, remote_ip: Optional[str] = None) -> CaptchaVerificationResult:
        """
        Verify a CAPTCHA token.
        
        :param token: The CAPTCHA response token from the frontend widget
        :param remote_ip: Optional IP address of the user for additional validation
        :return: CaptchaVerificationResult with verification status and risk assessment
        """
        pass
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the name of the CAPTCHA provider."""
        pass
    
    @property
    @abstractmethod
    def site_key(self) -> str:
        """Return the site/public key for this provider."""
        pass


class BotProtectionError(Exception):
    """Exception raised when bot protection operations fail."""
    pass


class RateLimitExceededError(Exception):
    """Exception raised when rate limit is exceeded."""
    def __init__(self, message: str, retry_after: Optional[int] = None):
        super().__init__(message)
        self.retry_after = retry_after


class SuspiciousActivityError(Exception):
    """Exception raised when suspicious activity is detected."""
    def __init__(self, message: str, risk_level: RiskLevel = RiskLevel.HIGH):
        super().__init__(message)
        self.risk_level = risk_level
