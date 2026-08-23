"""CAPTCHA provider abstraction (CONTRACTS.md §0).

Vendor-agnostic async interface for CAPTCHA/bot-protection providers
(hCaptcha, reCAPTCHA, Turnstile, ...).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

__all__ = [
    "RiskLevel",
    "CaptchaVerificationResult",
    "BehavioralAnalysis",
    "AbstractCaptchaProvider",
    "BotProtectionError",
    "RateLimitExceededError",
    "SuspiciousActivityError",
]


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
    #: Behavioral/analysis flags attached by the manager (may be empty).
    flags: List[str] = field(default_factory=list)
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
    """Abstract base class for CAPTCHA providers."""

    @abstractmethod
    async def verify_token(
        self, token: str, remote_ip: Optional[str] = None
    ) -> CaptchaVerificationResult:
        """Verify a CAPTCHA token and return the assessment."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the name of the CAPTCHA provider."""

    @property
    @abstractmethod
    def site_key(self) -> str:
        """Return the site/public key for this provider."""


class BotProtectionError(Exception):
    """Raised when a bot-protection operation fails."""


class RateLimitExceededError(Exception):
    """Raised when a rate limit is exceeded; carries ``retry_after``."""

    def __init__(self, message: str, retry_after: Optional[int] = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class SuspiciousActivityError(Exception):
    """Raised when suspicious activity is detected."""

    def __init__(self, message: str, risk_level: RiskLevel = RiskLevel.HIGH) -> None:
        super().__init__(message)
        self.risk_level = risk_level
