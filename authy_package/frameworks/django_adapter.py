"""Django Integration Adapter"""

from functools import wraps
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser
from asgiref.sync import async_to_sync
import asyncio


class DjangoAuth:
    """
    Django authentication adapter
    
    Usage:
        from authy_package import init_auth
        from authy_package.frameworks import DjangoAuth
        
        auth = init_auth(config)
        django_auth = DjangoAuth(auth)
        
        # Use middleware
        MIDDLEWARE = [
            'authy_package.frameworks.DjangoAuthMiddleware',
        ]
        
        # Or use decorator
        @django_auth.require_auth
        def protected_view(request):
            return JsonResponse({'user': request.user.email})
    """
    
    def __init__(self, auth_manager):
        self.auth_manager = auth_manager
    
    def _get_token_from_request(self, request) -> str:
        """Extract JWT token from request"""
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
        return None
    
    def require_auth(self, f):
        """Decorator to require authentication"""
        @wraps(f)
        def decorated_function(request, *args, **kwargs):
            token = self._get_token_from_request(request)
            
            if not token:
                return JsonResponse({'error': 'Missing authorization token'}, status=401)
            
            try:
                payload = async_to_sync(self.auth_manager.verify_token)(token)
                
                if not payload:
                    return JsonResponse({'error': 'Invalid token'}, status=401)
                
                user_id = payload.get('sub')
                user = async_to_sync(self.auth_manager.db.get_user)(user_id)
                
                if not user:
                    return JsonResponse({'error': 'User not found'}, status=401)
                
                # Attach user to request
                request.current_user = user
                request.token_payload = payload
                
                return f(request, *args, **kwargs)
                
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=401)
        
        return decorated_function
    
    def require_role(self, *roles):
        """Decorator to require specific roles"""
        def decorator(f):
            @wraps(f)
            def decorated_function(request, *args, **kwargs):
                if not hasattr(request, 'current_user'):
                    return JsonResponse({'error': 'Authentication required'}, status=401)
                
                user = request.current_user
                user_role = user.get('role')
                
                org_id = request.META.get('HTTP_X_ORGANIZATION_ID')
                
                if org_id:
                    org_role = async_to_sync(
                        self.auth_manager.organizations.get_member_role
                    )(org_id, user['id'])
                    
                    if not org_role or org_role.value not in roles:
                        return JsonResponse({'error': 'Insufficient permissions'}, status=403)
                elif user_role not in roles:
                    return JsonResponse({'error': 'Insufficient permissions'}, status=403)
                
                return f(request, *args, **kwargs)
            
            return decorated_function
        return decorator
    
    def optional_auth(self, f):
        """Decorator for optional authentication"""
        @wraps(f)
        def decorated_function(request, *args, **kwargs):
            token = self._get_token_from_request(request)
            
            if token:
                try:
                    payload = async_to_sync(self.auth_manager.verify_token)(token)
                    
                    if payload:
                        user_id = payload.get('sub')
                        user = async_to_sync(self.auth_manager.db.get_user)(user_id)
                        request.current_user = user
                except Exception:
                    pass  # Continue without auth
            
            return f(request, *args, **kwargs)
        
        return decorated_function


class DjangoAuthMiddleware(MiddlewareMixin):
    """Django middleware for automatic authentication"""
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        from authy_package import get_auth
        self.auth_manager = get_auth()
        self.django_auth = DjangoAuth(self.auth_manager)
    
    def process_request(self, request):
        """Authenticate request if token present"""
        token = self.django_auth._get_token_from_request(request)
        
        if token:
            try:
                payload = async_to_sync(self.auth_manager.verify_token)(token)
                
                if payload:
                    user_id = payload.get('sub')
                    user = async_to_sync(self.auth_manager.db.get_user)(user_id)
                    
                    if user:
                        request.current_user = user
                        request.token_payload = payload
            except Exception:
                pass  # Continue without auth
        
        return None
