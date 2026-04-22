"""
FastAPI Integration Adapter

Features:
- One-line dependency injection
- Automatic token verification
- User context injection
- Role-based route protection
- Organization-aware middleware
"""

from typing import Optional, List, Any
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from functools import wraps


class FastAPIAuth:
    """
    FastAPI authentication adapter
    
    Usage:
        from authy_package import AuthConfig, init_auth
        from authy_package.frameworks import FastAPIAuth
        
        config = AuthConfig.from_env()
        auth = init_auth(config)
        fastapi_auth = FastAPIAuth(auth)
        
        @app.get("/protected")
        async def protected_route(user=Depends(fastapi_auth.require_auth())):
            return {"user": user}
        
        @app.get("/admin")
        async def admin_route(user=Depends(fastapi_auth.require_role("admin"))):
            return {"message": "Admin access granted"}
    """
    
    def __init__(self, auth_manager):
        self.auth_manager = auth_manager
        self.security = HTTPBearer(auto_error=False)
    
    async def get_current_user(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
    ) -> Optional[dict]:
        """Get current authenticated user from JWT token"""
        if not credentials:
            return None
        
        token = credentials.credentials
        
        try:
            payload = await self.auth_manager.verify_token(token)
            if not payload:
                return None
            
            user_id = payload.get("sub")
            if not user_id:
                return None
            
            user = await self.auth_manager.db.get_user(user_id)
            return user
            
        except Exception:
            return None
    
    async def require_auth(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = None
    ) -> dict:
        """Require authentication - raises 401 if not authenticated"""
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        token = credentials.credentials
        
        try:
            payload = await self.auth_manager.verify_token(token)
            if not payload:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            user_id = payload.get("sub")
            session_id = payload.get("session_id")
            
            # Validate session
            if session_id:
                session = await self.auth_manager.sessions.validate_session(token)
                if not session:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session expired or revoked",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
            
            user = await self.auth_manager.db.get_user(user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            return user
            
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication failed: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    def require_role(self, *roles: str):
        """
        Decorator to require specific roles
        
        Usage:
            @app.get("/admin")
            async def admin_route(user=Depends(fastapi_auth.require_role("admin", "owner"))):
                pass
        """
        async def role_checker(
            user: dict = Depends(self.require_auth),
            request: Request = None
        ) -> dict:
            user_role = user.get("role")
            org_id = request.headers.get("X-Organization-ID") if request else None
            
            if org_id:
                # Check organization-specific role
                org_role = await self.auth_manager.organizations.get_member_role(org_id, user["id"])
                if not org_role or org_role.value not in roles:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Insufficient permissions",
                    )
            elif user_role not in roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions",
                )
            
            return user
        
        return role_checker
    
    def require_org_membership(self):
        """Require user to be member of specified organization"""
        async def org_checker(
            user: dict = Depends(self.require_auth),
            request: Request = None
        ) -> dict:
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Organization ID required",
                )
            
            org_id = request.headers.get("X-Organization-ID")
            if not org_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="X-Organization-ID header required",
                )
            
            org = await self.auth_manager.organizations.get_organization(org_id)
            if not org:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Organization not found",
                )
            
            role = await self.auth_manager.organizations.get_member_role(org_id, user["id"])
            if not role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not a member of this organization",
                )
            
            # Add organization context to user
            user["current_org"] = {
                "id": org.id,
                "name": org.name,
                "role": role.value
            }
            
            return user
        
        return org_checker
    
    async def optional_auth(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
    ) -> Optional[dict]:
        """Optional authentication - returns None if not authenticated"""
        if not credentials:
            return None
        
        return await self.get_current_user(credentials)
    
    def rate_limit(self, requests: int, seconds: int):
        """
        Rate limiting decorator
        
        Usage:
            @app.post("/login")
            async def login(user=Depends(fastapi_auth.rate_limit(5, 60))):
                pass
        """
        async def rate_limiter(request: Request):
            ip = request.client.host
            key = f"rate_limit:{ip}:{request.url.path}"
            
            count = await self.auth_manager.cache.get(key)
            if count and int(count) >= requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded",
                )
            
            await self.auth_manager.cache.incr(key)
            await self.auth_manager.cache.expire(key, seconds)
            
            return True
        
        return rate_limiter
