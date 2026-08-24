"""Bot protection manager (CONTRACTS.md §0, §3, §3.1).

Layers of defense around CAPTCHA verification:

- Sliding-window rate limiting backed by the §3 cache list primitives
  (``lpush``/``lrange``/``expire``); expired timestamps are trimmed on every
  read so windows cannot grow unbounded.
- Behavioral heuristics for user agents and IP addresses. The IP checks are
  an HONEST local heuristic (loopback / link-local / cloud metadata ranges),
  not threat intelligence — they flag "not a typical public client address".
- Risk scoring in [0.0, 1.0] combined coherently: CAPTCHA failures and
  behavioral flags can only RAISE risk, never lower a provider verdict.

Rate-limit keys live in the §3.1 ``tessera:ratelimit:{scope}:{id}`` namespace.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from typing import Any, Dict, List, Optional

from tessera.cache import AbstractCache, InMemoryCache

from .abstract_provider import (
    AbstractCaptchaProvider,
    BehavioralAnalysis,
    BotProtectionError,
    CaptchaVerificationResult,
    RateLimitExceededError,
    RiskLevel,
)

logger = logging.getLogger("tessera.bot_protection.manager")

__all__ = ["BotProtectionManager"]

#: Cloud instance-metadata IPs seen in SSRF abuse; requests claiming these
#: source addresses are almost never real end-user clients.
_CLOUD_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254"})

#: Upper bound for the per-action analytics ledger.
_ACTION_LOG_MAX_ENTRIES = 100


class BotProtectionManager:
    """Manages CAPTCHA verification, rate limiting and behavioral analysis.

    Features:
    - CAPTCHA verification (hCaptcha, reCAPTCHA, ...) via a provider
    - Sliding-window per-minute/per-hour rate limiting (cache list primitives)
    - User-agent and IP heuristics (documented as heuristics, not TI feeds)
    - Coherent combined risk scoring with configurable thresholds
    """

    #: Common bot indicators in user agents (substring match, lower-cased).
    BOT_USER_AGENT_PATTERNS = [
        "bot",
        "crawler",
        "spider",
        "scraper",
        "curl",
        "wget",
        "python-requests",
        "httpx",
        "java/",
        "go-http-client",
    ]

    def __init__(
        self,
        provider: Optional[AbstractCaptchaProvider],
        cache: Optional[AbstractCache] = None,
        *,
        enable_rate_limiting: bool = True,
        enable_behavioral_analysis: bool = True,
        max_requests_per_minute: int = 10,
        max_requests_per_hour: int = 100,
        captcha_required_actions: Optional[List[str]] = None,
        risk_threshold_medium: float = 0.5,
        risk_threshold_high: float = 0.8,
    ) -> None:
        """Initialize the manager.

        Args:
            provider: CAPTCHA provider; ``None`` disables CAPTCHA checks but
                still allows rate limiting and behavioral analysis.
            cache: AbstractCache implementation; defaults to a private
                :class:`InMemoryCache` (single-process only).
            enable_rate_limiting: Toggle the sliding-window limiter.
            enable_behavioral_analysis: Toggle UA/IP heuristics.
            max_requests_per_minute: Per-identifier minute budget.
            max_requests_per_hour: Per-identifier hour budget.
            captcha_required_actions: Actions that always require CAPTCHA.
            risk_threshold_medium: Score at or above which risk is MEDIUM.
            risk_threshold_high: Score at or above which risk is HIGH.
        """
        if max_requests_per_minute <= 0 or max_requests_per_hour <= 0:
            raise ValueError("rate limits must be positive")
        if not 0.0 < risk_threshold_medium <= risk_threshold_high <= 1.0:
            raise ValueError("risk thresholds must satisfy 0 < medium <= high <= 1")

        self.provider = provider
        self.cache: AbstractCache = cache if cache is not None else InMemoryCache()
        self.enable_rate_limiting = enable_rate_limiting
        self.enable_behavioral_analysis = enable_behavioral_analysis
        self.max_requests_per_minute = max_requests_per_minute
        self.max_requests_per_hour = max_requests_per_hour
        self.captcha_required_actions = captcha_required_actions or [
            "login",
            "register",
            "password_reset",
        ]
        self.risk_threshold_medium = risk_threshold_medium
        self.risk_threshold_high = risk_threshold_high

    # -- key schema (§3.1) ------------------------------------------------------

    @staticmethod
    def _rate_limit_key(identifier: str, window: str) -> str:
        """Sliding-window list key in the §3.1 ratelimit namespace."""
        return f"tessera:ratelimit:bot:{window}:{identifier}"

    # -- sliding window primitives ------------------------------------------------

    async def _window_count(self, key: str, window_seconds: int) -> int:
        """Count timestamps inside ``window_seconds`` and trim the rest.

        Trimming keeps the stored list bounded (the AbstractCache contract has
        no ``ltrim`` primitive, so the list is rebuilt from the surviving
        entries). TTL is refreshed on every maintenance pass.
        """
        now = time.time()
        cutoff = now - window_seconds
        raw = await self.cache.lrange(key, 0, -1)

        kept: List[str] = []
        for value in raw:
            try:
                ts = float(value)
            except (TypeError, ValueError):
                continue  # drop malformed entries
            if ts > cutoff:
                kept.append(value)

        if len(kept) != len(raw):
            await self.cache.delete(key)
            if kept:
                # kept is newest-first (lpush order); reinsert preserving order.
                await self.cache.lpush(key, *reversed(kept))

        if kept:
            await self.cache.expire(key, window_seconds)
        return len(kept)

    async def check_rate_limit(self, identifier: str) -> bool:
        """Record a request and enforce per-minute/per-hour budgets.

        Args:
            identifier: Unique scope id (e.g. ``"login:user@example.com"``).

        Returns:
            ``True`` when the request is within limits.

        Raises:
            RateLimitExceededError: When a budget is exhausted; carries
                ``retry_after`` seconds.
        """
        if not self.enable_rate_limiting:
            return True

        minute_key = self._rate_limit_key(identifier, "minute")
        minute_count = await self._window_count(minute_key, 60)
        if minute_count >= self.max_requests_per_minute:
            logger.warning("Per-minute rate limit exceeded for %s", identifier)
            raise RateLimitExceededError(
                f"Rate limit exceeded: {minute_count} requests in the last minute",
                retry_after=60,
            )

        hour_key = self._rate_limit_key(identifier, "hour")
        hour_count = await self._window_count(hour_key, 3600)
        if hour_count >= self.max_requests_per_hour:
            logger.warning("Per-hour rate limit exceeded for %s", identifier)
            raise RateLimitExceededError(
                f"Rate limit exceeded: {hour_count} requests in the last hour",
                retry_after=3600,
            )

        timestamp = str(time.time())
        await self.cache.lpush(minute_key, timestamp)
        await self.cache.expire(minute_key, 60)
        await self.cache.lpush(hour_key, timestamp)
        await self.cache.expire(hour_key, 3600)
        return True

    # -- behavioral heuristics ---------------------------------------------------

    def analyze_user_agent(self, user_agent: Optional[str]) -> BehavioralAnalysis:
        """Analyze a user agent string for bot indicators (heuristic)."""
        flags: List[str] = []
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
            if len(user_agent) < 20:
                flags.append("short_user_agent")
                risk_score += 0.2

        return BehavioralAnalysis(
            is_suspicious=len(flags) > 0,
            risk_score=min(risk_score, 1.0),
            flags=flags,
            details={"user_agent": user_agent},
        )

    def analyze_ip_address(self, ip_address: Optional[str]) -> BehavioralAnalysis:
        """Analyze a client IP with a LOCAL heuristic (not threat intelligence).

        Flags addresses that are implausible as public end-user clients:
        unparseable values, cloud instance-metadata endpoints, link-local,
        loopback and RFC1918/ULA private ranges. Real deployments should pair
        this with a threat-intelligence feed.
        """
        flags: List[str] = []
        risk_score = 0.0

        if not ip_address:
            flags.append("missing_ip")
            risk_score += 0.3
            return BehavioralAnalysis(
                is_suspicious=True,
                risk_score=risk_score,
                flags=flags,
                details={"ip_address": None},
            )

        try:
            addr = ipaddress.ip_address(ip_address)
        except ValueError:
            flags.append("unparseable_ip")
            return BehavioralAnalysis(
                is_suspicious=True,
                risk_score=0.3,
                flags=flags,
                details={"ip_address": ip_address},
            )

        if ip_address in _CLOUD_METADATA_IPS:
            flags.append("cloud_metadata_ip")
            risk_score += 0.8
        elif addr.is_link_local:
            flags.append("link_local_ip")
            risk_score += 0.4
        elif addr.is_loopback:
            flags.append("loopback_ip")
            risk_score += 0.4
        elif addr.is_private:
            flags.append("private_range_ip")
            risk_score += 0.2

        return BehavioralAnalysis(
            is_suspicious=len(flags) > 0,
            risk_score=min(risk_score, 1.0),
            flags=flags,
            details={"ip_address": ip_address},
        )

    # -- CAPTCHA ----------------------------------------------------------------

    async def verify_captcha(
        self,
        token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        action: Optional[str] = None,
    ) -> CaptchaVerificationResult:
        """Verify a CAPTCHA token and layer behavioral analysis on top.

        Behavioral risk can only RAISE the provider's risk assessment; a
        successful CAPTCHA is never silently downgraded below MEDIUM signals.

        Raises:
            BotProtectionError: When no provider is configured.
        """
        if self.provider is None:
            raise BotProtectionError(
                "No CAPTCHA provider configured; cannot verify tokens"
            )

        result = await self.provider.verify_token(token, remote_ip=ip_address)

        if self.enable_behavioral_analysis:
            ua_analysis = self.analyze_user_agent(user_agent)
            ip_analysis = self.analyze_ip_address(ip_address)
            behavioral_risk = max(ua_analysis.risk_score, ip_analysis.risk_score)
            behavior_flags = ua_analysis.flags + ip_analysis.flags

            if behavioral_risk > 0.0:
                result.risk_score = min(
                    result.risk_score + behavioral_risk * 0.5, 1.0
                )
                result.risk_level = self._calculate_risk_level(result.risk_score)
                result.flags.extend(behavior_flags)

                if behavioral_risk > 0.8:
                    result.is_human = False

        return result

    def _calculate_risk_level(self, risk_score: float) -> RiskLevel:
        """Map a score in [0, 1] to a RiskLevel using configured thresholds."""
        if risk_score >= self.risk_threshold_high:
            return RiskLevel.HIGH
        if risk_score >= self.risk_threshold_medium:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    async def should_require_captcha(
        self, action: str, risk_score: float = 0.0
    ) -> bool:
        """Decide whether CAPTCHA is required for ``action``."""
        if action in self.captcha_required_actions:
            return True
        return risk_score >= self.risk_threshold_high

    async def record_action(
        self, identifier: str, action: str, success: bool
    ) -> None:
        """Append an action to a bounded 24h analytics ledger."""
        key = f"tessera:bot:action:{identifier}:{action}"
        entry = json.dumps({"timestamp": time.time(), "success": bool(success)})
        await self.cache.lpush(key, entry)
        # Bounded ledger: trim anything beyond the newest N entries.
        all_entries = await self.cache.lrange(key, 0, -1)
        if len(all_entries) > _ACTION_LOG_MAX_ENTRIES:
            await self.cache.delete(key)
            await self.cache.lpush(
                key, *reversed(all_entries[:_ACTION_LOG_MAX_ENTRIES])
            )
        await self.cache.expire(key, 86400)
