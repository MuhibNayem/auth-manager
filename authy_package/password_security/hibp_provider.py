"""
Have I Been Pwned (HIBP) Provider for Authy Package.

Checks if passwords have been exposed in known data breaches using the
Pwned Passwords API with k-anonymity for privacy.

Privacy Note:
    This implementation uses k-anonymity - only the first 5 characters of the
    SHA1 hash are sent to the API. The full password never leaves your server.

Configuration:
    Option 1 - Direct initialization:
        provider = HibpProvider(api_key="your_api_key")
    
    Option 2 - Environment variables (recommended):
        HIBP_API_KEY=your_api_key
        
        provider = HibpProvider.from_env()
    
    Option 3 - No API key (rate limited):
        provider = HibpProvider()  # Uses unauthenticated endpoint

Usage:
    is_breached, count = await provider.check_password("password123")
    
    if is_breached:
        print(f"This password has been breached {count} times!")
    else:
        print("Password not found in breach database.")

API Key:
    Get a free API key at: https://haveibeenpwned.com/API/v3#Authorisation
    API key provides higher rate limits and supports the full API.
"""

import hashlib
import os
from typing import Optional, Tuple
from dataclasses import dataclass

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    httpx = None


@dataclass
class HibpConfig:
    """HIBP configuration."""
    api_key: Optional[str] = None
    base_url: str = "https://api.pwnedpasswords.com"
    timeout_seconds: float = 5.0
    use_range_api: bool = True  # Use k-anonymity range API
    
    @classmethod
    def from_env(cls) -> 'HibpConfig':
        """Load configuration from environment variables."""
        api_key = os.getenv("HIBP_API_KEY")
        return cls(api_key=api_key)


class HibpProvider:
    """
    Have I Been Pwned password breach checker.
    
    Features:
    - K-anonymity for privacy (only partial hash sent)
    - Async HTTP requests
    - Configurable API key support
    - Comprehensive error handling
    - Rate limit awareness
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout_seconds: float = 5.0
    ):
        """
        Initialize HIBP provider.
        
        :param api_key: HIBP API key (optional but recommended)
        :param base_url: API base URL
        :param timeout_seconds: Request timeout in seconds
        """
        if not HTTPX_AVAILABLE:
            raise ImportError(
                "httpx library not installed. Install with: pip install httpx"
            )
        
        # Load from config or environment
        if api_key:
            self.config = HibpConfig(
                api_key=api_key,
                base_url=base_url or HibpConfig.base_url,
                timeout_seconds=timeout_seconds
            )
        else:
            self.config = HibpConfig.from_env()
            if base_url:
                self.config.base_url = base_url
            self.config.timeout_seconds = timeout_seconds
        
        self._client: Optional[httpx.AsyncClient] = None
    
    @property
    async def client(self) -> httpx.AsyncClient:
        """Lazy initialization of HTTP client."""
        if self._client is None or self._client.is_closed:
            headers = {}
            if self.config.api_key:
                headers["hibp-api-key"] = self.config.api_key
            
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                headers=headers
            )
        return self._client
    
    def _hash_password(self, password: str) -> str:
        """
        Hash password using SHA1.
        
        :param password: Plain text password
        :return: Uppercase hex SHA1 hash
        """
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest()
        return sha1_hash.upper()
    
    async def check_password(self, password: str) -> Tuple[bool, int]:
        """
        Check if a password has been breached.
        
        :param password: Password to check
        :return: Tuple of (is_breached, breach_count)
        :raises: Exception on API errors
        """
        # Hash the password
        sha1_hash = self._hash_password(password)
        
        # Split hash for k-anonymity
        prefix = sha1_hash[:5]  # First 5 characters
        suffix = sha1_hash[5:]   # Remaining 35 characters
        
        # Make API request
        client = await self.client
        url = f"{self.config.base_url}/range/{prefix}"
        
        try:
            response = await client.get(url)
            
            if response.status_code == 404:
                # Password not found in database
                return False, 0
            
            response.raise_for_status()
            
            # Parse response (format: SUFFIX:COUNT per line)
            lines = response.text.strip().split('\n')
            
            for line in lines:
                if ':' in line:
                    hash_suffix, count_str = line.split(':')
                    if hash_suffix.upper() == suffix:
                        count = int(count_str)
                        return count > 0, count
            
            # Suffix not found in response
            return False, 0
            
        except httpx.TimeoutException as e:
            raise Exception(f"HIBP API timeout: {str(e)}")
        except httpx.HTTPError as e:
            raise Exception(f"HIBP API error: {response.status_code} - {str(e)}")
        except Exception as e:
            raise Exception(f"Failed to check password: {str(e)}")
    
    async def check_password_safe(self, password: str) -> Tuple[bool, int, Optional[str]]:
        """
        Check if a password has been breached with error handling.
        
        :param password: Password to check
        :return: Tuple of (is_breached, breach_count, error_message)
        """
        try:
            is_breached, count = await self.check_password(password)
            return is_breached, count, None
        except Exception as e:
            # On error, assume safe but log the issue
            return False, 0, str(e)
    
    async def get_breach_stats(self) -> Optional[dict]:
        """
        Get general breach statistics from HIBP.
        
        :return: Dictionary with breach statistics or None on error
        """
        client = await self.client
        url = f"{self.config.base_url}/breaches"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            breaches = response.json()
            
            return {
                "total_breaches": len(breaches),
                "total_pastes": None,  # Would need separate API call
                "last_updated": None
            }
        except Exception:
            return None
    
    async def close(self):
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
    
    @classmethod
    def from_env(cls, **kwargs) -> 'HibpProvider':
        """
        Create HibpProvider from environment variables.
        
        :param kwargs: Additional arguments to override environment values
        :return: Configured HibpProvider instance
        """
        config = HibpConfig.from_env()
        return cls(
            api_key=kwargs.get('api_key', config.api_key),
            base_url=kwargs.get('base_url', config.base_url),
            timeout_seconds=kwargs.get('timeout_seconds', config.timeout_seconds)
        )
