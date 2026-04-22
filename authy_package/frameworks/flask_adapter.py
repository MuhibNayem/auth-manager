"""Flask Integration Adapter"""

from functools import wraps
from flask import request, jsonify, g, current_app
from typing import Optional, Callable, Any


class FlaskAuth:
    """
    Flask authentication adapter
    
    Usage:
        from authy_package import init_auth
        from authy_package.frameworks import FlaskAuth
        
        auth = init_auth(config)
        flask_auth = FlaskAuth(auth)
        
        @app.route('/protected')
        @flask_auth.require_auth
        def protected():
            return jsonify(user=g.current_user)
        
        @app.route('/admin')
        @flask_auth.require_role('admin')
        def admin():
            return jsonify(message='Admin access')
    """
    
    def __init__(self, auth_manager):
        self.auth_manager = auth_manager
    
    async def _get_token_from_request(self) -> Optional[str]:
        """Extract JWT token from request"""
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
        return None
    
    def require_auth(self, f: Callable) -> Callable:
        """Decorator to require authentication"""
        @wraps(f)
        async def decorated_function(*args, **kwargs):
            import asyncio
            
            token = await self._get_token_from_request()
            if not token:
                return jsonify({"error": "Missing authorization token"}), 401
            
            try:
                # Run async code in sync context
                loop = asyncio.get_event_loop()
                payload = await loop.run_in_executor(
                    None, 
                    lambda: asyncio.run(self.auth_manager.verify_token(token))
                )
                
                if not payload:
                    return jsonify({"error": "Invalid token"}), 401
                
                user_id = payload.get("sub")
                user = await loop.run_in_executor(
                    None,
                    lambda: asyncio.run(self.auth_manager.db.get_user(user_id))
                )
                
                if not user:
                    return jsonify({"error": "User not found"}), 401
                
                g.current_user = user
                g.token_payload = payload
                
                return f(*args, **kwargs)
                
            except Exception as e:
                return jsonify({"error": str(e)}), 401
        
        return decorated_function
    
    def require_role(self, *roles: str) -> Callable:
        """Decorator to require specific roles"""
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            async def decorated_function(*args, **kwargs):
                if not hasattr(g, 'current_user'):
                    return jsonify({"error": "Authentication required"}), 401
                
                user = g.current_user
                user_role = user.get("role")
                
                org_id = request.headers.get("X-Organization-ID")
                
                if org_id:
                    loop = asyncio.get_event_loop()
                    org_role = await loop.run_in_executor(
                        None,
                        lambda: asyncio.run(
                            self.auth_manager.organizations.get_member_role(org_id, user["id"])
                        )
                    )
                    if not org_role or org_role.value not in roles:
                        return jsonify({"error": "Insufficient permissions"}), 403
                elif user_role not in roles:
                    return jsonify({"error": "Insufficient permissions"}), 403
                
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
    
    def optional_auth(self, f: Callable) -> Callable:
        """Decorator for optional authentication"""
        @wraps(f)
        async def decorated_function(*args, **kwargs):
            import asyncio
            
            token = await self._get_token_from_request()
            if token:
                try:
                    loop = asyncio.get_event_loop()
                    payload = await loop.run_in_executor(
                        None,
                        lambda: asyncio.run(self.auth_manager.verify_token(token))
                    )
                    
                    if payload:
                        user_id = payload.get("sub")
                        user = await loop.run_in_executor(
                            None,
                            lambda: asyncio.run(self.auth_manager.db.get_user(user_id))
                        )
                        g.current_user = user
                except Exception:
                    pass  # Continue without auth
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    def rate_limit(self, requests: int, seconds: int) -> Callable:
        """Rate limiting decorator"""
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            async def decorated_function(*args, **kwargs):
                import asyncio
                
                ip = request.remote_addr
                key = f"rate_limit:{ip}:{request.path}"
                
                loop = asyncio.get_event_loop()
                count = await loop.run_in_executor(
                    None,
                    lambda: asyncio.run(self.auth_manager.cache.get(key))
                )
                
                if count and int(count) >= requests:
                    return jsonify({"error": "Rate limit exceeded"}), 429
                
                await loop.run_in_executor(
                    None,
                    lambda: asyncio.run(self.auth_manager.cache.incr(key))
                )
                await loop.run_in_executor(
                    None,
                    lambda: asyncio.run(self.auth_manager.cache.expire(key, seconds))
                )
                
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
