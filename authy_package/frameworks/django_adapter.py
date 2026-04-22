"""Django Integration Adapter

Note: Django imports are lazy to avoid configuration errors.
Set DJANGO_SETTINGS_MODULE environment variable before using.
"""

from functools import wraps


class DjangoAuth:
    """
    Django authentication adapter (lazy loading)

    Usage:
        from authy_package import init_auth
        from authy_package.frameworks import DjangoAuth

        auth = init_auth(config)
        django_auth = DjangoAuth(auth)
    """

    def __init__(self, auth_manager):
        self.auth_manager = auth_manager
        # Import Django components lazily
        self._django_loaded = False

    def _load_django(self):
        if not self._django_loaded:
            from django.http import JsonResponse
            from django.utils.deprecation import MiddlewareMixin
            from django.contrib.auth.models import AnonymousUser
            from asgiref.sync import async_to_sync
            import asyncio
            
            self.JsonResponse = JsonResponse
            self.MiddlewareMixin = MiddlewareMixin
            self.AnonymousUser = AnonymousUser
            self.async_to_sync = async_to_sync
            self.asyncio = asyncio
            self._django_loaded = True

    def require_auth(self, view_func):
        """Decorator to require authentication on Django views"""
        self._load_django()
        
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            
            if not auth_header.startswith('Bearer '):
                return self.JsonResponse({'error': 'Unauthorized'}, status=401)
            
            token = auth_header.split(' ')[1]
            
            try:
                user = self.async_to_sync(self.auth_manager.verify_token)(token)
                if not user:
                    return self.JsonResponse({'error': 'Invalid token'}, status=401)
                
                request.user = user
                return view_func(request, *args, **kwargs)
            except Exception as e:
                return self.JsonResponse({'error': str(e)}, status=401)
        
        return wrapper


class DjangoAuthMiddleware:
    """Django middleware for automatic authentication"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.auth_manager = None
    
    def __call__(self, request):
        # Lazy initialization
        if self.auth_manager is None:
            from authy_package import get_auth
            self.auth_manager = get_auth()
        
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                from asgiref.sync import async_to_sync
                user = async_to_sync(self.auth_manager.verify_token)(token)
                if user:
                    request.auth_user = user
            except:
                pass
        
        response = self.get_response(request)
        return response
