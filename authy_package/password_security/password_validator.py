"""
Password Validator for Authy Package.

Provides comprehensive password validation with configurable policies,
strength scoring, and breached password checking.
"""

import re
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass, field

from .hibp_provider import HibpProvider


@dataclass
class PasswordPolicy:
    """
    Configurable password policy.
    
    Usage:
        policy = PasswordPolicy(
            min_length=12,
            max_length=128,
            require_uppercase=True,
            require_lowercase=True,
            require_numbers=True,
            require_special_chars=True,
            special_chars="!@#$%^&*()_+-=[]{}|;:,.<>?",
            check_breached=True,
            min_breach_count=1,  # Reject if breached this many times
            disallow_common_passwords=True,
            disallow_sequential_chars=True,
            disallow_repeated_chars=True
        )
    """
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special_chars: bool = True
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?/"
    check_breached: bool = True
    min_breach_count: int = 1  # Reject if breach count >= this
    disallow_common_passwords: bool = True
    disallow_sequential_chars: bool = True
    disallow_repeated_chars: bool = True
    max_repeated_chars: int = 3
    disallow_username_in_password: bool = True


@dataclass
class PasswordStrengthResult:
    """Result of password strength analysis."""
    is_valid: bool = False
    strength_score: float = 0.0  # 0.0 to 1.0
    strength_level: str = "weak"  # weak, fair, good, strong, very_strong
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    is_breached: bool = False
    breach_count: int = 0


class PasswordSecurityManager:
    """
    Manages password security validation.
    
    Features:
    - Configurable password policies
    - Strength scoring algorithm
    - Breached password detection
    - Common password detection
    - Sequential character detection
    - Personalized error messages
    """
    
    # Common passwords list (top 50 - expand in production)
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'shadow', '123123', '654321', 'superman',
        'qazwsx', 'michael', 'football', 'password1', 'password123',
        'welcome', 'jesus', 'ninja', 'mustang', 'password1234',
        'admin', 'admin123', 'root', 'toor', 'pass', 'test',
        'guest', 'master', 'changeme', '123456789', '1234567890'
    }
    
    # Sequential patterns to detect
    SEQUENTIAL_PATTERNS = [
        'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij',
        'ijk', 'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr',
        'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
        '012', '123', '234', '345', '456', '567', '678', '789',
        '890', 'cba', 'dcb', 'edc', 'fed', 'gfe', 'hgf', 'ihg',
        'jih', 'kji', 'lkj', 'mlk', 'nml', 'onm', 'pon', 'qpo',
        'rqp', 'srq', 'tsr', 'uts', 'vut', 'wvu', 'xwv', 'yxw',
        'zyx', '210', '321', '432', '543', '654', '765', '876',
        '987', '098'
    ]
    
    def __init__(
        self,
        hibp_provider: Optional[HibpProvider] = None,
        policy: Optional[PasswordPolicy] = None,
        cache: Optional[Any] = None
    ):
        """
        Initialize Password Security Manager.
        
        :param hibp_provider: HIBP provider for breach checking
        :param policy: Password policy configuration
        :param cache: Cache for storing breach check results
        """
        self.hibp_provider = hibp_provider
        self.policy = policy or PasswordPolicy()
        self.cache = cache
        
        # In-memory cache fallback
        self._breach_cache: Dict[str, Tuple[bool, int]] = {}
    
    def _check_length(self, password: str) -> Tuple[bool, Optional[str]]:
        """Check password length requirements."""
        if len(password) < self.policy.min_length:
            return False, f"Password must be at least {self.policy.min_length} characters long"
        if len(password) > self.policy.max_length:
            return False, f"Password must be no more than {self.policy.max_length} characters"
        return True, None
    
    def _check_uppercase(self, password: str) -> Tuple[bool, Optional[str]]:
        """Check for uppercase letters."""
        if self.policy.require_uppercase and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        return True, None
    
    def _check_lowercase(self, password: str) -> Tuple[bool, Optional[str]]:
        """Check for lowercase letters."""
        if self.policy.require_lowercase and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        return True, None
    
    def _check_numbers(self, password: str) -> Tuple[bool, Optional[str]]:
        """Check for numbers."""
        if self.policy.require_numbers and not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        return True, None
    
    def _check_special_chars(self, password: str) -> Tuple[bool, Optional[str]]:
        """Check for special characters."""
        if self.policy.require_special_chars:
            pattern = f"[{re.escape(self.policy.special_chars)}]"
            if not re.search(pattern, password):
                return False, f"Password must contain at least one special character ({self.policy.special_chars})"
        return True, None
    
    def _check_common_password(self, password: str) -> Tuple[bool, Optional[str]]:
        """Check against common passwords list."""
        if self.policy.disallow_common_passwords:
            if password.lower() in self.COMMON_PASSWORDS:
                return False, "Password is too common and easily guessable"
        return True, None
    
    def _check_sequential_chars(self, password: str) -> Tuple[bool, Optional[str]]:
        """Check for sequential characters."""
        if self.policy.disallow_sequential_chars:
            password_lower = password.lower()
            for pattern in self.SEQUENTIAL_PATTERNS:
                if pattern in password_lower:
                    return False, "Password contains sequential characters (e.g., abc, 123)"
        return True, None
    
    def _check_repeated_chars(self, password: str) -> Tuple[bool, Optional[str]]:
        """Check for repeated characters."""
        if self.policy.disallow_repeated_chars:
            pattern = r'(.)\1{' + str(self.policy.max_repeated_chars) + r',}'
            if re.search(pattern, password):
                return False, f"Password contains too many repeated characters (max {self.policy.max_repeated_chars})"
        return True, None
    
    def _check_username_in_password(self, password: str, username: Optional[str]) -> Tuple[bool, Optional[str]]:
        """Check if username is contained in password."""
        if self.policy.disallow_username_in_password and username:
            if len(username) >= 3 and username.lower() in password.lower():
                return False, "Password cannot contain your username"
        return True, None
    
    async def _check_breached(self, password: str) -> Tuple[bool, int, Optional[str]]:
        """Check if password has been breached."""
        if not self.policy.check_breached or not self.hibp_provider:
            return False, 0, None
        
        # Check cache first
        cache_key = f"breach:{hash(password)}"
        if cache_key in self._breach_cache:
            is_breached, count = self._breach_cache[cache_key]
            return is_breached, count, None
        
        try:
            is_breached, count = await self.hibp_provider.check_password(password)
            
            # Cache the result
            self._breach_cache[cache_key] = (is_breached, count)
            
            if is_breached and count >= self.policy.min_breach_count:
                return True, count, f"This password has been found in {count} known data breaches"
            
            return is_breached, count, None
            
        except Exception as e:
            # Log error but don't fail validation
            return False, 0, f"Could not check breach database: {str(e)}"
    
    def _calculate_strength_score(
        self,
        password: str,
        errors: List[str],
        warnings: List[str]
    ) -> Tuple[float, str]:
        """
        Calculate password strength score.
        
        :return: Tuple of (score, level)
        """
        score = 0.0
        
        # Length scoring (up to 30 points)
        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 10:
            score += 20
        elif length >= 8:
            score += 15
        else:
            score += 5
        
        # Character variety scoring (up to 40 points)
        char_types = 0
        if re.search(r'[A-Z]', password):
            char_types += 1
        if re.search(r'[a-z]', password):
            char_types += 1
        if re.search(r'\d', password):
            char_types += 1
        if re.search(r'[^A-Za-z0-9]', password):
            char_types += 1
        
        score += char_types * 10
        
        # Penalty for errors (up to -40 points)
        score -= len(errors) * 10
        
        # Penalty for warnings (up to -10 points)
        score -= len(warnings) * 2
        
        # Ensure score is between 0 and 100
        score = max(0, min(100, score))
        
        # Convert to 0-1 scale
        normalized_score = score / 100.0
        
        # Determine level
        if normalized_score >= 0.9:
            level = "very_strong"
        elif normalized_score >= 0.7:
            level = "strong"
        elif normalized_score >= 0.5:
            level = "good"
        elif normalized_score >= 0.3:
            level = "fair"
        else:
            level = "weak"
        
        return normalized_score, level
    
    async def validate_password(
        self,
        password: str,
        username: Optional[str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validate a password against the configured policy.
        
        :param password: Password to validate
        :param username: Optional username for personalized checks
        :return: Tuple of (is_valid, list_of_errors)
        """
        errors = []
        warnings = []
        suggestions = []
        
        # Run all checks
        checks = [
            self._check_length(password),
            self._check_uppercase(password),
            self._check_lowercase(password),
            self._check_numbers(password),
            self._check_special_chars(password),
            self._check_common_password(password),
            self._check_sequential_chars(password),
            self._check_repeated_chars(password),
            self._check_username_in_password(password, username)
        ]
        
        for is_valid, error in checks:
            if not is_valid and error:
                errors.append(error)
        
        # Check breached passwords (async)
        is_breached, breach_count, breach_error = await self._check_breached(password)
        
        if is_breached:
            errors.append(f"This password has been compromised in {breach_count} data breaches")
        
        if breach_error:
            warnings.append(breach_error)
        
        # Generate suggestions
        if len(password) < 16:
            suggestions.append("Consider using a longer password (16+ characters)")
        if not re.search(r'[^A-Za-z0-9]', password):
            suggestions.append("Add special characters (!@#$%^&*)")
        if self.policy.disallow_common_passwords and password.lower() in self.COMMON_PASSWORDS:
            suggestions.append("Avoid common passwords and phrases")
        
        is_valid = len(errors) == 0
        
        return is_valid, errors
    
    async def assess_password_strength(
        self,
        password: str,
        username: Optional[str] = None
    ) -> PasswordStrengthResult:
        """
        Assess overall password strength with detailed feedback.
        
        :param password: Password to assess
        :param username: Optional username for personalized checks
        :return: PasswordStrengthResult with comprehensive analysis
        """
        errors = []
        warnings = []
        suggestions = []
        
        # Run all validation checks
        is_valid, validation_errors = await self.validate_password(password, username)
        errors.extend(validation_errors)
        
        # Calculate strength score
        score, level = self._calculate_strength_score(password, errors, warnings)
        
        # Check if breached
        is_breached = False
        breach_count = 0
        if self.policy.check_breached and self.hibp_provider:
            is_breached, breach_count, _ = await self._check_breached(password)
        
        # Generate additional suggestions based on score
        if score < 0.5:
            suggestions.append("Use a mix of uppercase, lowercase, numbers, and symbols")
            suggestions.append("Avoid dictionary words and personal information")
        elif score < 0.7:
            suggestions.append("Consider adding more unique characters")
        
        return PasswordStrengthResult(
            is_valid=is_valid,
            strength_score=score,
            strength_level=level,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions,
            is_breached=is_breached,
            breach_count=breach_count
        )
