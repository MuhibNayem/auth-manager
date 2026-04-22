"""
Passwordless Authentication - Magic Links

Features:
- One-click login via email
- Time-limited tokens
- Automatic user creation
- Click tracking and analytics
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt


class MagicLinkManager:
    """
    Magic link authentication for passwordless login
    
    Usage:
        magic_mgr = MagicLinkManager(config, db, cache, email_service)
        await magic_mgr.send_magic_link("user@example.com")
        user = await magic_mgr.verify_magic_link(token)
    """
    
    def __init__(self, config, db, cache, email_service):
        self.config = config
        self.db = db
        self.cache = cache
        self.email_service = email_service
        self._token_prefix = "magic_link:"
        self._token_expiry_seconds = 600  # 10 minutes
    
    async def send_magic_link(
        self,
        email: str,
        redirect_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send a magic link to the user's email
        
        Args:
            email: User's email address
            redirect_url: URL to redirect after login
            metadata: Additional data to include in token
        
        Returns:
            True if email sent successfully
        """
        # Generate token
        token = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(seconds=self._token_expiry_seconds)
        
        # Store token in cache
        token_data = {
            "email": email,
            "redirect_url": redirect_url or self.config.default_redirect_url,
            "metadata": metadata or {},
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at.isoformat(),
            "used": False
        }
        
        await self.cache.set(
            f"{self._token_prefix}{token}",
            token_data,
            ttl=self._token_expiry_seconds
        )
        
        # Generate magic link URL
        magic_link = f"{self.config.base_url}/auth/magic?token={token}"
        
        # Send email
        email_sent = await self.email_service.send_magic_link_email(
            to=email,
            magic_link=magic_link,
            expires_in_minutes=self._token_expiry_seconds // 60
        )
        
        # Track event
        await self._track_event("magic_link_sent", email, {"redirect_url": redirect_url})
        
        return email_sent
    
    async def verify_magic_link(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify magic link token and return user data
        
        Args:
            token: Magic link token
        
        Returns:
            User data dict if valid, None otherwise
        """
        # Get token from cache
        token_data = await self.cache.get(f"{self._token_prefix}{token}")
        
        if not token_data:
            await self._track_event("magic_link_failed", None, {"reason": "token_not_found"})
            return None
        
        # Check if already used
        if token_data.get("used"):
            await self._track_event("magic_link_failed", None, {"reason": "already_used"})
            return None
        
        # Check expiration
        expires_at = datetime.fromisoformat(token_data["expires_at"])
        if datetime.utcnow() > expires_at:
            await self.cache.delete(f"{self._token_prefix}{token}")
            await self._track_event("magic_link_failed", None, {"reason": "expired"})
            return None
        
        email = token_data["email"]
        
        # Mark token as used
        token_data["used"] = True
        await self.cache.set(
            f"{self._token_prefix}{token}",
            token_data,
            ttl=60  # Keep for 1 minute to prevent replay
        )
        
        # Find or create user
        user = await self.db.get_user_by_email(email)
        
        if not user:
            # Auto-create user if enabled
            if self.config.auto_create_users:
                user = await self.db.create_user({
                    "email": email,
                    "email_verified": True,
                    "auth_method": "magic_link",
                    "created_at": datetime.utcnow().isoformat()
                })
                await self._track_event("user_created", email, {"method": "magic_link"})
            else:
                await self._track_event("magic_link_failed", email, {"reason": "user_not_found"})
                return None
        
        # Track successful login
        await self._track_event("magic_link_verified", email, {"user_id": user.get("id")})
        
        return {
            "user": user,
            "redirect_url": token_data.get("redirect_url"),
            "metadata": token_data.get("metadata")
        }
    
    async def resend_magic_link(self, email: str) -> bool:
        """Resend magic link to the same email (rate limited)"""
        # Check rate limit
        rate_key = f"magic_link_rate:{email}"
        attempts = await self.cache.get(rate_key)
        
        if attempts and int(attempts) >= 3:
            return False  # Rate limited
        
        # Send new magic link
        sent = await self.send_magic_link(email)
        
        if sent:
            # Increment rate limit counter
            await self.cache.incr(rate_key)
            await self.cache.expire(rate_key, 300)  # 5 minute window
        
        return sent
    
    async def _track_event(self, event_type: str, email: Optional[str], metadata: Dict[str, Any]):
        """Track magic link events for analytics"""
        event = {
            "event_type": event_type,
            "email": email,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata
        }
        
        # Store in database for analytics
        await self.db.save_auth_event(event)
