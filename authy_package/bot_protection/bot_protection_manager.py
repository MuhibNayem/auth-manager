"""
Bot Protection Manager for Authy Package.

Provides comprehensive bot protection with CAPTCHA verification, rate limiting,
and behavioral analysis.

Usage:
    from authy_package.bot_protection import BotProtectionManager, hCaptchaProvider
    
    # Setup provider
    provider = hCaptchaProvider.from_env()
    
    # Create manager with cache (Redis recommended)
    bot_manager = BotProtectionManager(
        provider=provider,
        cache=redis_cache_instance,
        enable_rate_limiting=True,
        max_requests_per_minute=10
    )
    
    # Verify CAPTCHA on login
    result = await bot_manager.verify_captcha(
        token="captcha_token_from_frontend",
        ip_address=request.client.host,
        action="login"
    )
    
    if not result.is_human:
        raise SuspiciousActivityError("Bot detected!")
    
    # Check rate limit
    is_allowed = await bot_manager.check_rate_limit("login:user@example.com")
"""

import time
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta

from .abstract_provider import (
    AbstractCaptchaProvider,
    CaptchaVerificationResult,
    BehavioralAnalysis,
    BotProtectionError,
    RateLimitExceededError,
    SuspiciousActivityError,
    RiskLevel
)


class BotProtectionManager:
    """
    Manages bot protection with multiple layers of defense.
    
    Features:
    - CAPTCHA verification (hCaptcha, reCAPTCHA, etc.)
    - Rate limiting per user/IP/action
    - Behavioral analysis (user agent, IP patterns, etc.)
    - Configurable risk thresholds
    - Comprehensive logging and monitoring
    """
    
    # Common bot indicators in user agents
    BOT_USER_AGENT_PATTERNS = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
        'python-requests', 'httpx', 'java/', 'go-http-client'
    ]
    
    # Suspicious IP patterns (simplified - use real threat intelligence in production)
    SUSPICIOUS_IP_PATTERNS = []
    
    def __init__(
        self,
        provider: AbstractCaptchaProvider,
        cache: Optional[Any] = None,
        enable_rate_limiting: bool = True,
        enable_behavioral_analysis: bool = True,
        max_requests_per_minute: int = 10,
        max_requests_per_hour: int = 100,
        captcha_required_actions: Optional[List[str]] = None,
        risk_threshold_medium: float = 0.5,
        risk_threshold_high: float = 0.8
    ):
        """
        Initialize Bot Protection Manager.
        
        :param provider: CAPTCHA provider instance
        :param cache: Cache instance for rate limiting (Redis recommended)
        :param enable_rate_limiting: Enable rate limiting
        :param enable_behavioral_analysis: Enable behavioral analysis
        :param max_requests_per_minute: Max requests per minute per identifier
        :param max_requests_per_hour: Max requests per hour per identifier
        :param captcha_required_actions: Actions that always require CAPTCHA
        :param risk_threshold_medium: Risk score threshold for medium risk
        :param risk_threshold_high: Risk score threshold for high risk
        """
        self.provider = provider
        self.cache = cache
        self.enable_rate_limiting = enable_rate_limiting
        self.enable_behavioral_analysis = enable_behavioral_analysis
        self.max_requests_per_minute = max_requests_per_minute
        self.max_requests_per_hour = max_requests_per_hour
        self.captcha_required_actions = captcha_required_actions or ["login", "register", "password_reset"]
        self.risk_threshold_medium = risk_threshold_medium
        self.risk_threshold_high = risk_threshold_high
        
        # In-memory fallback if no cache provided
        self._memory_store: Dict[str, List[float]] = {}
    
    def _get_rate_limit_key(self, identifier: str, window: str) -> str:
        """Generate rate limit cache key."""
        return f"ratelimit:{identifier}:{window}"
    
    async def _store_request_timestamp(self, key: str, timestamp: float, ttl: int):
        """Store request timestamp in cache."""
        if self.cache:
            # Use Redis list to store timestamps
            await self.cache.lpush(key, str(timestamp))
            await self.cache.expire(key, ttl)
        else:
            if key not in self._memory_store:
                self._memory_store[key] = []
            self._memory_store[key].append(timestamp)
            # Clean old entries
            cutoff = time.time() - ttl
            self._memory_store[key] = [ts for ts in self._memory_store[key] if ts > cutoff]
    
    async def _get_request_count(self, key: str, window_seconds: int) -> int:
        """Get request count in the specified window."""
        current_time = time.time()
        cutoff = current_time - window_seconds
        
        if self.cache:
            # Get all timestamps from Redis list
            timestamps = await self.cache.lrange(key, 0, -1)
            if not timestamps:
                return 0
            # Count timestamps within window
            return sum(1 for ts in timestamps if float(ts) > cutoff)
        else:
            if key not in self._memory_store:
                return 0
            return sum(1 for ts in self._memory_store[key] if ts > cutoff)
    
    async def check_rate_limit(self, identifier: str) -> bool:
        """
        Check if an identifier has exceeded rate limits.
        
        :param identifier: Unique identifier (e.g., "login:user@example.com" or IP address)
        :return: True if within limits, False if exceeded
        :raises: RateLimitExceededError if limit exceeded
        """
        if not self.enable_rate_limiting:
            return True
        
        current_time = time.time()
        
        # Check per-minute limit
        minute_key = self._get_rate_limit_key(identifier, "minute")
        minute_count = await self._get_request_count(minute_key, 60)
        
        if minute_count >= self.max_requests_per_minute:
            raise RateLimitExceededError(
                f"Rate limit exceeded: {minute_count} requests in the last minute",
                retry_after=60
            )
        
        # Check per-hour limit
        hour_key = self._get_rate_limit_key(identifier, "hour")
        hour_count = await self._get_request_count(hour_key, 3600)
        
        if hour_count >= self.max_requests_per_hour:
            raise RateLimitExceededError(
                f"Rate limit exceeded: {hour_count} requests in the last hour",
                retry_after=3600
            )
        
        # Record this request
        await self._store_request_timestamp(minute_key, current_time, 60)
        await self._store_request_timestamp(hour_key, current_time, 3600)
        
        return True
    
    def analyze_user_agent(self, user_agent: Optional[str]) -> BehavioralAnalysis:
        """
        Analyze user agent for bot indicators.
        
        :param user_agent: User agent string from request
        :return: BehavioralAnalysis with findings
        """
        flags = []
        risk_score = 0.0
        
        if not user_agent:
            flags.append("missing_user_agent")
            risk_score += 0.5
        else:
            ua_lower = user_agent.lower()
            for pattern in self.BOT_USER_AGENT_PATTERNS:
                if pattern in ua_lower:
                    flags.append(f"bot_pattern:{pattern}")
                    risk_score += 0.3
                    break
            
            # Check for very short user agents (often bots)
            if len(user_agent) < 20:
                flags.append("short_user_agent")
                risk_score += 0.2
        
        return BehavioralAnalysis(
            is_suspicious=len(flags) > 0,
            risk_score=min(risk_score, 1.0),
            flags=flags,
            details={"user_agent": user_agent}
        )
    
    def analyze_ip_address(self, ip_address: Optional[str]) -> BehavioralAnalysis:
        """
        Analyze IP address for suspicious patterns.
        
        :param ip_address: IP address from request
        :return: BehavioralAnalysis with findings
        """
        flags = []
        risk_score = 0.0
        
        if not ip_address:
            flags.append("missing_ip")
            risk_score += 0.3
        else:
            # Check for known suspicious patterns
            for pattern in self.SUSPICIOUS_IP_PATTERNS:
                if ip_address.startswith(pattern):
                    flags.append(f"suspicious_ip_pattern:{pattern}")
                    risk_score += 0.5
        
        return BehavioralAnalysis(
            is_suspicious=len(flags) > 0,
            risk_score=min(risk_score, 1.0),
            flags=flags,
            details={"ip_address": ip_address}
        )
    
    async def verify_captcha(
        self,
        token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        action: Optional[str] = None
    ) -> CaptchaVerificationResult:
        """
        Verify CAPTCHA token with additional behavioral checks.
        
        :param token: CAPTCHA response token from frontend
        :param ip_address: Client IP address
        :param user_agent: Client user agent string
        :param action: Action being performed (login, register, etc.)
        :return: CaptchaVerificationResult with comprehensive assessment
        """
        # Verify CAPTCHA with provider
        result = await self.provider.verify_token(token, remote_ip=ip_address)
        
        # Add behavioral analysis if enabled
        if self.enable_behavioral_analysis:
            ua_analysis = self.analyze_user_agent(user_agent)
            ip_analysis = self.analyze_ip_address(ip_address)
            
            # Combine risk scores
            behavioral_risk = max(ua_analysis.risk_score, ip_analysis.risk_score)
            
            # Adjust final risk score
            if behavioral_risk > 0.5:
                result.risk_score = min(result.risk_score + behavioral_risk * 0.5, 1.0)
                result.risk_level = self._calculate_risk_level(result.risk_score)
                
                # Flag as non-human if behavioral risk is very high
                if behavioral_risk > 0.8:
                    result.is_human = False
                    result.flags = getattr(result, 'flags', []) + ua_analysis.flags + ip_analysis.flags
        
        return result
    
    def _calculate_risk_level(self, risk_score: float) -> RiskLevel:
        """Calculate risk level from score."""
        if risk_score >= self.risk_threshold_high:
            return RiskLevel.HIGH
        elif risk_score >= self.risk_threshold_medium:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    async def should_require_captcha(self, action: str, risk_score: float = 0.0) -> bool:
        """
        Determine if CAPTCHA should be required for an action.
        
        :param action: The action being performed
        :param risk_score: Current risk score from other analyses
        :return: True if CAPTCHA is required
        """
        # Always require for certain actions
        if action in self.captcha_required_actions:
            return True
        
        # Require if risk score is high
        if risk_score >= self.risk_threshold_high:
            return True
        
        return False
    
    async def record_action(self, identifier: str, action: str, success: bool):
        """
        Record an action for analytics and pattern detection.
        
        :param identifier: User identifier
        :param action: Action performed
        :param success: Whether the action was successful
        """
        if not self.cache:
            return
        
        key = f"action:{identifier}:{action}"
        data = {
            "timestamp": time.time(),
            "success": success
        }
        
        # Store for pattern analysis (could be enhanced with ML in future)
        await self.cache.lpush(key, str(data))
        await self.cache.expire(key, 86400)  # Keep for 24 hours
