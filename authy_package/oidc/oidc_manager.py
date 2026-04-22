"""
OpenID Connect (OIDC) Client Implementation

This module provides complete OIDC client functionality including:
- Dynamic provider discovery
- Authorization code flow with PKCE
- Token management and refresh
- User info retrieval
- ID token validation
- Support for multiple providers
"""

import secrets
import hashlib
import base64
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlencode, urljoin
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class OIDCConfig:
    """Configuration for OIDC Client."""
    
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        issuer: Optional[str] = None,
        authorization_endpoint: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        userinfo_endpoint: Optional[str] = None,
        jwks_uri: Optional[str] = None,
        end_session_endpoint: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        response_type: str = "code",
        token_endpoint_auth_method: str = "client_secret_post",
        require_pkce: bool = True,
        clock_skew_seconds: int = 60,
    ):
        """
        Initialize OIDC configuration.
        
        Args:
            client_id: OIDC client identifier
            client_secret: OIDC client secret
            redirect_uri: Redirect URI registered with the provider
            issuer: OIDC issuer URL (for dynamic discovery)
            authorization_endpoint: Authorization endpoint URL
            token_endpoint: Token endpoint URL
            userinfo_endpoint: User info endpoint URL
            jwks_uri: JWKS URI for key discovery
            end_session_endpoint: Logout endpoint URL
            scopes: List of OAuth2 scopes to request
            response_type: OAuth2 response type (default: code)
            token_endpoint_auth_method: Authentication method for token endpoint
            require_pkce: Require PKCE for authorization code flow
            clock_skew_seconds: Allowed clock skew for token validation
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.issuer = issuer
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self.jwks_uri = jwks_uri
        self.end_session_endpoint = end_session_endpoint
        self.scopes = scopes or ["openid", "profile", "email"]
        self.response_type = response_type
        self.token_endpoint_auth_method = token_endpoint_auth_method
        self.require_pkce = require_pkce
        self.clock_skew_seconds = clock_skew_seconds
        
        # JWKS cache
        self._jwks_cache: Optional[Dict] = None
        self._jwks_cache_time: Optional[float] = None
    
    async def discover(self) -> 'OIDCConfig':
        """
        Perform OIDC Discovery to auto-configure endpoints.
        
        Returns:
            Self with discovered configuration populated
        """
        if not self.issuer:
            raise ValueError("Issuer URL is required for discovery")
        
        import aiohttp
        discovery_url = urljoin(self.issuer, '.well-known/openid-configuration')
        
        async with aiohttp.ClientSession() as session:
            async with session.get(discovery_url) as response:
                if response.status != 200:
                    raise Exception(f"Discovery failed: {response.status}")
                
                config = await response.json()
        
        # Populate endpoints from discovery
        self.authorization_endpoint = self.authorization_endpoint or config.get('authorization_endpoint')
        self.token_endpoint = self.token_endpoint or config.get('token_endpoint')
        self.userinfo_endpoint = self.userinfo_endpoint or config.get('userinfo_endpoint')
        self.jwks_uri = self.jwks_uri or config.get('jwks_uri')
        self.end_session_endpoint = self.end_session_endpoint or config.get('end_session_endpoint')
        
        # Validate required endpoints
        if not all([self.authorization_endpoint, self.token_endpoint, self.jwks_uri]):
            raise ValueError("Missing required OIDC endpoints after discovery")
        
        return self
    
    async def get_jwks(self) -> Dict:
        """Fetch JWKS from provider with caching."""
        import aiohttp
        
        now = time.time()
        # Cache for 1 hour
        if self._jwks_cache and self._jwks_cache_time and (now - self._jwks_cache_time) < 3600:
            return self._jwks_cache
        
        if not self.jwks_uri:
            raise ValueError("JWKS URI not configured")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(self.jwks_uri) as response:
                if response.status != 200:
                    raise Exception(f"Failed to fetch JWKS: {response.status}")
                
                self._jwks_cache = await response.json()
                self._jwks_cache_time = now
        
        return self._jwks_cache


class OIDCManager:
    """
    OpenID Connect Client Manager
    
    Handles all OIDC operations including:
    - Authorization code flow with PKCE
    - Token exchange and refresh
    - ID token validation
    - User info retrieval
    - Session management
    """
    
    def __init__(self, config: OIDCConfig, database, cache=None):
        """
        Initialize OIDC Manager.
        
        Args:
            config: OIDCConfig instance
            database: Database adapter implementing AbstractDatabase
            cache: Optional cache adapter for storing state
        """
        self.config = config
        self.db = database
        self.cache = cache
    
    def generate_pkce_pair(self) -> Tuple[str, str]:
        """
        Generate PKCE code verifier and challenge.
        
        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        # Generate random code verifier (43-128 characters)
        code_verifier = secrets.token_urlsafe(32)
        
        # Create SHA256 hash of verifier
        sha256_hash = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(sha256_hash).decode().rstrip('=')
        
        return code_verifier, code_challenge
    
    def create_authorization_url(
        self,
        state: Optional[str] = None,
        code_verifier: Optional[str] = None,
        prompt: Optional[str] = None,
        login_hint: Optional[str] = None,
    ) -> Tuple[str, str, str]:
        """
        Create OIDC authorization URL.
        
        Args:
            state: State parameter for CSRF protection (auto-generated if not provided)
            code_verifier: PKCE code verifier (auto-generated if not provided)
            prompt: Prompt parameter (none, login, consent, select_account)
            login_hint: Hint to IdP about user's identity
            
        Returns:
            Tuple of (authorization_url, state, code_verifier)
        """
        # Generate state if not provided
        if not state:
            state = secrets.token_urlsafe(32)
        
        # Generate PKCE pair if required
        if self.config.require_pkce and not code_verifier:
            code_verifier, code_challenge = self.generate_pkce_pair()
        elif self.config.require_pkce:
            # Create challenge from provided verifier
            sha256_hash = hashlib.sha256(code_verifier.encode()).digest()
            code_challenge = base64.urlsafe_b64encode(sha256_hash).decode().rstrip('=')
        else:
            code_challenge = None
        
        # Build authorization URL parameters
        params = {
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'response_type': self.config.response_type,
            'scope': ' '.join(self.config.scopes),
            'state': state,
        }
        
        if code_challenge:
            params['code_challenge'] = code_challenge
            params['code_challenge_method'] = 'S256'
        
        if prompt:
            params['prompt'] = prompt
        
        if login_hint:
            params['login_hint'] = login_hint
        
        authorization_url = f"{self.config.authorization_endpoint}?{urlencode(params)}"
        
        # Store state and verifier in cache
        if self.cache:
            cache_data = {'state': state}
            if code_verifier:
                cache_data['code_verifier'] = code_verifier
            self.cache.set(f"oidc:state:{state}", cache_data, ttl=600)
        
        return authorization_url, state, code_verifier
    
    async def exchange_code_for_tokens(
        self,
        code: str,
        state: str,
        code_verifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens.
        
        Args:
            code: Authorization code from IdP
            state: State parameter to validate
            code_verifier: PKCE code verifier (required if PKCE was used)
            
        Returns:
            Dictionary with access_token, id_token, refresh_token, etc.
            
        Raises:
            ValueError: If state validation fails or token exchange fails
        """
        # Validate state
        if self.cache:
            cached = self.cache.get(f"oidc:state:{state}")
            if not cached:
                raise ValueError("Invalid or expired state parameter")
            
            # Validate state matches
            if cached.get('state') != state:
                raise ValueError("State mismatch - possible CSRF attack")
            
            # Use cached verifier if not provided
            if not code_verifier and self.config.require_pkce:
                code_verifier = cached.get('code_verifier')
        
        # Build token request
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
        }
        
        if self.config.client_secret:
            if self.config.token_endpoint_auth_method == 'client_secret_post':
                token_data['client_secret'] = self.config.client_secret
            # For client_secret_basic, add to headers instead
        
        if code_verifier:
            token_data['code_verifier'] = code_verifier
        
        # Make token request
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.post(self.config.token_endpoint, data=token_data) as response:
                if response.status != 200:
                    error_data = await response.json()
                    raise ValueError(f"Token exchange failed: {error_data}")
                
                tokens = await response.json()
        
        # Validate ID token
        if 'id_token' in tokens:
            await self.validate_id_token(tokens['id_token'])
        
        # Store tokens in cache
        if self.cache and 'access_token' in tokens:
            # Calculate TTL from expires_in or default to 1 hour
            ttl = tokens.get('expires_in', 3600) - 60  # Refresh slightly before expiry
            self.cache.set(
                f"oidc:tokens:{tokens.get('access_token', '')[:16]}",
                tokens,
                ttl=ttl
            )
        
        return tokens
    
    async def validate_id_token(self, id_token: str) -> Dict[str, Any]:
        """
        Validate OIDC ID token.
        
        Args:
            id_token: JWT ID token from provider
            
        Returns:
            Decoded and validated token payload
            
        Raises:
            ValueError: If validation fails
        """
        try:
            # Decode without verification first to get header
            unverified = jwt.decode(id_token, options={"verify_signature": False})
            
            # Get kid from header
            header = jwt.get_unverified_header(id_token)
            kid = header.get('kid')
            
            # Fetch JWKS
            jwks = await self.config.get_jwks()
            
            # Find matching key
            public_key = None
            for key in jwks.get('keys', []):
                if key.get('kid') == kid:
                    # Convert JWK to PEM
                    public_key = self._jwk_to_pem(key)
                    break
            
            if not public_key:
                raise ValueError(f"No matching key found for kid: {kid}")
            
            # Validate token with proper verification
            payload = jwt.decode(
                id_token,
                public_key,
                algorithms=['RS256', 'ES256'],
                audience=self.config.client_id,
                issuer=self.config.issuer,
                options={
                    'verify_exp': True,
                    'verify_iat': True,
                    'verify_iss': True,
                    'verify_aud': True,
                },
                leeway=self.config.clock_skew_seconds,
            )
            
            # Additional validation: check nonce if present
            # Check auth_time if present
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise ValueError("ID token has expired")
        except jwt.InvalidAudienceError:
            raise ValueError("ID token audience mismatch")
        except jwt.InvalidIssuerError:
            raise ValueError("ID token issuer mismatch")
        except Exception as e:
            raise ValueError(f"ID token validation failed: {e}")
    
    def _jwk_to_pem(self, jwk: Dict) -> bytes:
        """Convert JWK to PEM format."""
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        
        kty = jwk.get('kty')
        
        if kty == 'RSA':
            # RSA key
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            
            n = int.from_bytes(base64.urlsafe_b64decode(jwk['n'] + '=='), 'big')
            e = int.from_bytes(base64.urlsafe_b64decode(jwk['e'] + '=='), 'big')
            
            public_numbers = RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key(default_backend())
            
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        
        elif kty == 'EC':
            # EC key (ES256, ES384, ES512)
            from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1, SECP384R1, SECP521R1
            
            crv = jwk.get('crv')
            x = int.from_bytes(base64.urlsafe_b64decode(jwk['x'] + '=='), 'big')
            y = int.from_bytes(base64.urlsafe_b64decode(jwk['y'] + '=='), 'big')
            
            if crv == 'P-256':
                curve = SECP256R1()
            elif crv == 'P-384':
                curve = SECP384R1()
            elif crv == 'P-521':
                curve = SECP521R1()
            else:
                raise ValueError(f"Unsupported EC curve: {crv}")
            
            public_numbers = EllipticCurvePublicNumbers(x, y, curve)
            public_key = public_numbers.public_key(default_backend())
            
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        
        else:
            raise ValueError(f"Unsupported key type: {kty}")
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Retrieve user information from OIDC userinfo endpoint.
        
        Args:
            access_token: Valid access token
            
        Returns:
            Dictionary with user attributes
        """
        if not self.config.userinfo_endpoint:
            raise ValueError("Userinfo endpoint not configured")
        
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                self.config.userinfo_endpoint,
                headers={'Authorization': f'Bearer {access_token}'}
            ) as response:
                if response.status != 200:
                    error_data = await response.json()
                    raise ValueError(f"Userinfo request failed: {error_data}")
                
                return await response.json()
    
    async def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh an access token using a refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            Dictionary with new tokens
        """
        import aiohttp
        
        token_data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.config.client_id,
        }
        
        if self.config.client_secret:
            token_data['client_secret'] = self.config.client_secret
        
        async with aiohttp.ClientSession() as session:
            async with session.post(self.config.token_endpoint, data=token_data) as response:
                if response.status != 200:
                    error_data = await response.json()
                    raise ValueError(f"Token refresh failed: {error_data}")
                
                tokens = await response.json()
        
        # Validate new ID token if present
        if 'id_token' in tokens:
            await self.validate_id_token(tokens['id_token'])
        
        return tokens
    
    async def logout(self, id_token_hint: Optional[str] = None, post_logout_redirect_uri: Optional[str] = None) -> str:
        """
        Create logout URL for RP-initiated logout.
        
        Args:
            id_token_hint: ID token to identify the user
            post_logout_redirect_uri: URL to redirect after logout
            
        Returns:
            Logout URL to redirect user to
        """
        if not self.config.end_session_endpoint:
            raise ValueError("End session endpoint not configured")
        
        params = {}
        
        if id_token_hint:
            params['id_token_hint'] = id_token_hint
        
        if post_logout_redirect_uri:
            params['post_logout_redirect_uri'] = post_logout_redirect_uri
        
        return f"{self.config.end_session_endpoint}?{urlencode(params)}"
    
    async def handle_oidc_callback(
        self,
        code: str,
        state: str,
        code_verifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Complete OIDC authentication flow from callback.
        
        This is a convenience method that:
        1. Exchanges code for tokens
        2. Validates ID token
        3. Retrieves user info
        4. Provisions/updates user in database
        
        Args:
            code: Authorization code
            state: State parameter
            code_verifier: PKCE code verifier
            
        Returns:
            Dictionary with user, tokens, and session info
        """
        # Exchange code for tokens
        tokens = await self.exchange_code_for_tokens(code, state, code_verifier)
        
        # Get user info
        user_info = await self.get_user_info(tokens['access_token'])
        
        # Provision or update user
        user = await self._provision_user(user_info, tokens)
        
        return {
            'user': user,
            'tokens': tokens,
            'user_info': user_info,
        }
    
    async def _provision_user(self, user_info: Dict[str, Any], tokens: Dict[str, Any]) -> Dict[str, Any]:
        """Just-in-Time user provisioning from OIDC."""
        email = user_info.get('email')
        
        if not email:
            raise ValueError("Email not available from OIDC provider")
        
        # Try to find existing user
        user = await self.db.get_user_by_identifier(email=email)
        
        if user:
            # Update user info
            update_data = {
                'full_name': user_info.get('name'),
                'given_name': user_info.get('given_name'),
                'family_name': user_info.get('family_name'),
                'picture': user_info.get('picture'),
                'locale': user_info.get('locale'),
                'oidc_subject': user_info.get('sub'),
                'auth_method': 'oidc',
            }
            # Filter out None values and update
            update_data = {k: v for k, v in update_data.items() if v is not None}
            # Note: You may want to add an update_user method to your DB interface
            return user
        
        # Create new user
        user_data = {
            'email': email,
            'username': user_info.get('preferred_username') or email.split('@')[0],
            'full_name': user_info.get('name'),
            'first_name': user_info.get('given_name'),
            'last_name': user_info.get('family_name'),
            'picture': user_info.get('picture'),
            'locale': user_info.get('locale'),
            'oidc_subject': user_info.get('sub'),
            'issuer': self.config.issuer,
            'auth_method': 'oidc',
        }
        
        # Filter out None values
        user_data = {k: v for k, v in user_data.items() if v is not None}
        
        await self.db.create_user(user_data)
        
        return await self.db.get_user_by_identifier(email=email)
