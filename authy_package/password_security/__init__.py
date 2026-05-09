"""
Password Security Module for Authy Package.

Provides enterprise-grade password security features including:
- Breached password detection via Have I Been Pwned API
- Password strength validation
- Configurable password policies

Quick Start:
    from authy_package.password_security import PasswordSecurityManager, HibpProvider
    
    # Initialize HIBP provider (uses environment variables or direct config)
    hibp_provider = HibpProvider.from_env()
    
    # Create password security manager
    password_manager = PasswordSecurityManager(
        hibp_provider=hibp_provider,
        min_length=12,
        require_uppercase=True,
        require_lowercase=True,
        require_numbers=True,
        require_special_chars=True,
        check_breached=True
    )
    
    # Validate a password
    is_valid, errors = await password_manager.validate_password("MySecureP@ss123")
    
    if is_valid:
        print("Password is secure!")
    else:
        print(f"Password issues: {errors}")

Environment Variables:
    HIBP_API_KEY=your_api_key  # Optional but recommended for production
"""

from .hibp_provider import HibpProvider, HibpConfig
from .password_validator import PasswordSecurityManager, PasswordPolicy, PasswordStrengthResult

__all__ = [
    "HibpProvider",
    "HibpConfig",
    "PasswordSecurityManager",
    "PasswordPolicy",
    "PasswordStrengthResult"
]
